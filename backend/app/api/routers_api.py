from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import allowed_router_names, ensure_router_allowed, get_current_user
from app.core import cache as cache_mod
from app.db import get_db
from app.integrations import traefik_client
from app.integrations.traefik_override import (
    crowdsec_bypass_active,
    is_crowdsec_enabled_on_router,
    remove_bypass_router,
    write_bypass_router,
)
from app.models import User
from app.schemas import CrowdsecToggleIn
from app.services.routers_view import build_router_rows, filter_rows_for_user
from app.settings import get_settings

router = APIRouter(prefix="/routers", tags=["routers"])


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
def toggle_crowdsec(
    router_name: str,
    body: CrowdsecToggleIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict:
    settings = get_settings()
    allowed = allowed_router_names(db, user)
    ensure_router_allowed(user, router_name, allowed)

    raw = traefik_client.fetch_routers_sync(db)
    match = next((r for r in raw if r.get("name") == router_name), None)
    if match is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Router not found")

    crowdsec_ref = settings.crowdsec_middleware
    middlewares = match.get("middlewares") or []
    label_has = is_crowdsec_enabled_on_router(middlewares, crowdsec_ref)

    if body.enabled:
        if not label_has:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CrowdSec is not declared on this router via Docker labels; add crowdsec@file first.",
            )
        remove_bypass_router(settings, router_name)
    else:
        if not label_has:
            return {"ok": True, "note": "Router had no CrowdSec middleware; nothing to disable."}
        write_bypass_router(
            settings,
            router_name=router_name,
            rule=str(match.get("rule") or ""),
            service=str(match.get("service") or ""),
            entry_points=match.get("entryPoints"),
            base_priority=int(match.get("priority") or 0),
        )

    cache_mod.invalidate_prefix("traefik:")
    bypass = crowdsec_bypass_active(settings, router_name)
    effective = bool(label_has and not bypass)
    return {"ok": True, "crowdsec_effective": effective, "bypass": bypass}
