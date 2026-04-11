from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import allowed_router_names, ensure_router_allowed, get_current_user
from app.core import cache as cache_mod
from app.db import get_db
from app.integrations import traefik_client
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
