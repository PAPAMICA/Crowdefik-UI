import re
import ssl
from urllib.parse import urlparse
from typing import Annotated, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import allowed_router_names, ensure_router_allowed, get_current_user
from app.core import cache as cache_mod
from app.db import get_db
from app.integrations import traefik_client
from app.integrations.instance_settings import get_or_create_instance_settings
from app.integrations.traefik_override import (
    crowdsec_effective,
    override_state,
    remove_override,
    write_override,
)
from app.models import User
from app.services.routers_view import build_router_rows, filter_rows_for_user
from app.settings import get_settings

router = APIRouter(prefix="/routers", tags=["routers"])


class CrowdsecActionIn(BaseModel):
    action: Literal["enable", "disable", "reset"]


class BulkActionIn(BaseModel):
    action: Literal["enable", "disable", "reset"]


def _extract_host_from_rule(rule: str) -> str | None:
    """Extract first hostname from a Traefik rule like Host(`foo.example.com`)."""
    m = re.search(r'Host\(`([^`]+)`\)', rule or "")
    return m.group(1) if m else None


@router.get("")
def list_routers(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> list[dict]:
    allowed = allowed_router_names(db, user)

    def factory():
        return traefik_client.fetch_routers_sync(db)

    raw = cache_mod.get_cached("traefik:routers", factory)
    rows = build_router_rows(raw)
    return filter_rows_for_user(rows, is_superuser=user.is_superuser, allowed_routers=allowed)


@router.get("/{router_name:path}/waf-test")
def waf_test(
    router_name: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict:
    """
    Probe the CrowdSec AppSec WAF by sending a malicious payload through
    Traefik's internal Docker address (avoids hairpin-NAT issues).

    Route:  backend  →  traefik:443  →  CrowdSec AppSec  →  (blocked 403 or pass-through)

    The Host header tells Traefik which router/middleware chain to use.
    Returns {blocked, status_code, url, probe_url, error?}.
    """
    allowed = allowed_router_names(db, user)
    ensure_router_allowed(user, router_name, allowed)

    raw = traefik_client.fetch_routers_sync(db)
    match = next((r for r in raw if r.get("name") == router_name), None)
    if match is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Router not found")

    host = _extract_host_from_rule(str(match.get("rule") or ""))
    if not host:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot extract hostname from router rule",
        )

    # Derive Traefik's internal hostname from the configured API URL
    # (e.g. http://traefik:8080  →  "traefik")
    instance = get_or_create_instance_settings(db)
    parsed = urlparse(str(instance.traefik_api_url))
    traefik_internal = parsed.hostname or "traefik"

    # XSS payload — triggers CrowdSec AppSec generic XSS rule
    payload = "?waf_probe=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    # URL used for display only (readable)
    display_url = f"https://{host}/{payload}"
    # Actual probe goes to Traefik's internal HTTPS port
    probe_url = f"https://{traefik_internal}{payload}"

    # Disable cert verification — we don't care about the cert of the internal endpoint
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        with httpx.Client(
            transport=httpx.HTTPTransport(ssl=ssl_ctx),
            timeout=8.0,
            follow_redirects=False,
        ) as client:
            r = client.get(
                probe_url,
                headers={
                    "Host": host,
                    "User-Agent": "Crowdefik-WAF-Probe/1.0",
                },
            )
            blocked = r.status_code in (403, 406)
            return {
                "blocked": blocked,
                "status_code": r.status_code,
                "url": display_url,
                "probe_url": probe_url,
            }
    except httpx.ConnectError as exc:
        return {
            "blocked": False,
            "status_code": None,
            "url": display_url,
            "probe_url": probe_url,
            "error": f"Cannot reach Traefik at {traefik_internal}:443 — {exc}",
        }
    except Exception as exc:
        return {
            "blocked": False,
            "status_code": None,
            "url": display_url,
            "probe_url": probe_url,
            "error": str(exc)[:300],
        }


@router.post("/crowdsec/bulk")
def bulk_crowdsec(
    body: BulkActionIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict:
    """Apply enable/disable/reset to all visible routers at once."""
    settings = get_settings()
    allowed = allowed_router_names(db, user)
    raw = traefik_client.fetch_routers_sync(db)
    rows = build_router_rows(raw)
    visible = filter_rows_for_user(rows, is_superuser=user.is_superuser, allowed_routers=allowed)

    ok = 0
    skipped = 0
    for r in visible:
        name = r["name"]
        rule = str(r.get("rule") or "")
        service = str(r.get("service") or "")
        entry_points = r.get("entry_points") or []
        base_priority = int(r.get("priority") or 0)

        if not rule or not service:
            skipped += 1
            continue

        if body.action == "enable":
            write_override(settings, router_name=name, rule=rule, service=service,
                           entry_points=entry_points, base_priority=base_priority, with_crowdsec=True)
        elif body.action == "disable":
            write_override(settings, router_name=name, rule=rule, service=service,
                           entry_points=entry_points, base_priority=base_priority, with_crowdsec=False)
        elif body.action == "reset":
            remove_override(settings, name)
        ok += 1

    cache_mod.invalidate_prefix("traefik:")
    return {"ok": True, "action": body.action, "applied": ok, "skipped": skipped}


@router.post("/{router_name:path}/crowdsec")
def set_crowdsec(
    router_name: str,
    body: CrowdsecActionIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict:
    settings = get_settings()
    allowed = allowed_router_names(db, user)
    ensure_router_allowed(user, router_name, allowed)

    raw = traefik_client.fetch_routers_sync(db)
    match = next((r for r in raw if r.get("name") == router_name), None)
    if match is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Router not found in Traefik")

    rule = str(match.get("rule") or "")
    service = str(match.get("service") or "")
    entry_points = match.get("entryPoints") or []
    base_priority = int(match.get("priority") or 0)

    if not rule or not service:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Router has no rule or service — cannot write override.",
        )

    if body.action == "enable":
        write_override(
            settings,
            router_name=router_name,
            rule=rule,
            service=service,
            entry_points=entry_points,
            base_priority=base_priority,
            with_crowdsec=True,
        )
    elif body.action == "disable":
        write_override(
            settings,
            router_name=router_name,
            rule=rule,
            service=service,
            entry_points=entry_points,
            base_priority=base_priority,
            with_crowdsec=False,
        )
    elif body.action == "reset":
        remove_override(settings, router_name)

    cache_mod.invalidate_prefix("traefik:")

    from app.integrations.traefik_override import is_crowdsec_enabled_on_router
    label_has = is_crowdsec_enabled_on_router(match.get("middlewares") or [], settings.crowdsec_middleware)
    new_state = override_state(settings, router_name)
    effective = crowdsec_effective(settings, router_name, label_has)

    return {
        "ok": True,
        "router": router_name,
        "override_state": new_state,
        "crowdsec_effective": effective,
    }
