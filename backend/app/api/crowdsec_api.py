from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import allowed_router_names, get_current_user
from app.core import cache as cache_mod
from app.db import get_db
from app.integrations import crowdsec_client, traefik_client
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
    if hosts is None:
        return decisions[:limit]
    return [d for d in decisions if blob_matches_hosts(d, hosts)][:limit]


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
        return alerts[:limit]
    return [a for a in alerts if blob_matches_hosts(a, hosts)][:limit]
