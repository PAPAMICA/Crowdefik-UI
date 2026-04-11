from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import allowed_router_names, get_current_user
from app.core import cache as cache_mod
from app.db import get_db
from app.integrations import crowdsec_client, traefik_client
from app.integrations.instance_settings import (
    crowdsec_api_key_plain,
    crowdsec_machine_password_plain,
    get_or_create_instance_settings,
)
from app.models import User
from app.services.routers_view import build_router_rows, filter_rows_for_user
from app.services.scope_filter import blob_matches_hosts, hosts_from_rules
from app.settings import get_settings

router = APIRouter(prefix="/crowdsec", tags=["crowdsec"])


def _visible_hosts(db: Session, user: User) -> set[str] | None:
    if user.is_superuser:
        return None
    allowed = allowed_router_names(db, user)

    def factory():
        return traefik_client.fetch_routers_sync(db)

    raw = cache_mod.get_cached("traefik:routers", factory)
    rows = build_router_rows(raw)
    visible = filter_rows_for_user(rows, is_superuser=False, allowed_routers=allowed)
    return hosts_from_rules(visible)


@router.get("/decisions")
def list_decisions(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    limit: int = 200,
) -> list[dict[str, Any]]:
    s = get_settings()

    def factory():
        return crowdsec_client.fetch_decisions_sync(db)

    decisions = cache_mod.get_cached("crowdsec:decisions", factory, ttl_seconds=s.crowdsec_cache_ttl_seconds)
    hosts = _visible_hosts(db, user)
    raw = decisions[:limit] if hosts is None else [d for d in decisions if blob_matches_hosts(d, hosts)][:limit]
    return _enrich_decisions_with_service(db, raw)


def _enrich_decisions_with_service(db: Session, decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add _target_host to each decision by looking up the most common alert target for that IP."""
    from sqlalchemy import func
    from app.models import StoredAlert
    ips = list({str(d.get("value") or d.get("ip") or "") for d in decisions if d.get("value") or d.get("ip")})
    if not ips:
        return decisions
    # For each IP, find the most common target_host in stored alerts
    rows = (
        db.query(StoredAlert.source_ip, StoredAlert.target_host, func.count(StoredAlert.id).label("n"))
        .filter(StoredAlert.source_ip.in_(ips), StoredAlert.target_host.isnot(None))
        .group_by(StoredAlert.source_ip, StoredAlert.target_host)
        .all()
    )
    # Pick the top host per IP
    from collections import defaultdict
    ip_hosts: dict[str, dict[str, int]] = defaultdict(dict)
    for ip, host, n in rows:
        ip_hosts[ip][host] = n
    top_host = {ip: max(hosts, key=hosts.__getitem__) for ip, hosts in ip_hosts.items()}
    for d in decisions:
        ip = str(d.get("value") or d.get("ip") or "")
        if ip in top_host:
            d["_target_host"] = top_host[ip]
    return decisions


@router.delete("/decisions/{decision_id}")
def unban_decision(
    decision_id: int,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Delete a CrowdSec decision (unban an IP)."""
    if not user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superuser required")
    result = crowdsec_client.delete_decision(db, decision_id)
    if not result.get("ok"):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=result.get("error", "Unknown error"))
    # Invalidate cache so the decision list refreshes
    cache_mod.invalidate_prefix("crowdsec:")
    return result


@router.get("/status")
def crowdsec_status(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return connectivity / auth status for CrowdSec (no external calls, just checks configuration)."""
    s = get_or_create_instance_settings(db)

    bouncer_ok = bool(crowdsec_api_key_plain(db))

    machine_id = getattr(s, "crowdsec_machine_id", None) or None
    machine_pass = crowdsec_machine_password_plain(db) if machine_id else None
    watcher_configured = bool(machine_id and machine_pass)

    return {
        "bouncer_configured": bouncer_ok,
        "watcher_configured": watcher_configured,
        "machine_id": machine_id,
        "lapi_url": s.crowdsec_lapi_url,
    }


@router.get("/alerts")
def list_alerts(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    limit: int = 200,
) -> list[dict[str, Any]]:
    s = get_settings()

    def factory():
        return crowdsec_client.fetch_alerts_sync(db)

    alerts = cache_mod.get_cached("crowdsec:alerts", factory, ttl_seconds=s.crowdsec_cache_ttl_seconds)
    hosts = _visible_hosts(db, user)
    if hosts is None:
        raw = alerts[:limit]
    else:
        raw = [a for a in alerts if blob_matches_hosts(a, hosts)][:limit]

    # Enrich each alert with stored target_host
    from app.models import StoredAlert
    ids = [a.get("id") for a in raw if isinstance(a.get("id"), int)]
    if ids:
        stored = {r.id: r.target_host for r in db.query(StoredAlert).filter(StoredAlert.id.in_(ids)).all()}
        for a in raw:
            a_id = a.get("id")
            if isinstance(a_id, int) and a_id in stored:
                a["_target_host"] = stored[a_id]
    return raw
