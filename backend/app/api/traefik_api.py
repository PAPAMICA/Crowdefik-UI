"""Traefik infrastructure API — overview, entrypoints, middlewares, TLS certs."""
import asyncio
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core import cache as cache_mod
from app.db import get_db
from app.integrations import traefik_client
from app.models import User

log = logging.getLogger(__name__)

router = APIRouter(prefix="/traefik", tags=["traefik"])


@router.get("/overview")
def traefik_overview(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return Traefik version, overview stats, entrypoints, and middlewares."""

    def routers_factory():
        return traefik_client.fetch_routers_sync(db)

    def middlewares_factory():
        return traefik_client.fetch_middlewares_sync(db)

    overview = cache_mod.get_cached("traefik:overview", lambda: traefik_client.fetch_overview_sync(db), ttl_seconds=30)
    entrypoints = cache_mod.get_cached("traefik:entrypoints", lambda: traefik_client.fetch_entrypoints_sync(db), ttl_seconds=60)
    middlewares = cache_mod.get_cached("traefik:middlewares", middlewares_factory, ttl_seconds=60)
    routers = cache_mod.get_cached("traefik:routers", routers_factory)
    services = cache_mod.get_cached("traefik:services", lambda: traefik_client.fetch_services_sync(db), ttl_seconds=60)

    # Compute counts
    tls_router_count = sum(1 for r in routers if r.get("tls"))
    active_ep = [e for e in entrypoints if not e.get("name", "").startswith("traefik")]

    return {
        "version": overview.get("version_detail", {}).get("Version") if overview.get("version_detail") else overview.get("version"),
        "code_name": overview.get("version_detail", {}).get("Codename"),
        "http_routers_total": len(routers),
        "http_routers_tls": tls_router_count,
        "http_services_total": len(services),
        "http_middlewares_total": len(middlewares),
        "entrypoints": [
            {
                "name": ep.get("name"),
                "address": ep.get("address"),
                "tls": "tls" in str(ep.get("name", "")).lower() or ep.get("address", "").endswith(":443"),
                "protocol": ep.get("transport", {}).get("respondingTimeouts", None) and "http" or "http",
            }
            for ep in active_ep
        ],
        "middlewares": [
            {
                "name": mw.get("name"),
                "type": mw.get("type"),
                "provider": mw.get("provider"),
                "status": mw.get("status"),
            }
            for mw in middlewares
        ],
        "features": overview.get("features", []),
    }


@router.get("/certs")
def traefik_certs(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    force: bool = False,
) -> dict[str, Any]:
    """Return TLS certificate info for all HTTPS routers.

    Results are cached for 1 hour (SSL probes are network-bound).
    Pass ?force=true to bypass the cache and re-probe immediately.
    """
    if force:
        cache_mod.invalidate_prefix("traefik:certs")

    try:
        certs = cache_mod.get_cached(
            "traefik:certs",
            lambda: traefik_client.fetch_tls_domains(db),
            ttl_seconds=3600,
        )
        return {"ok": True, "certs": certs}
    except Exception as exc:
        log.warning("TLS cert check failed: %s", exc)
        return {"ok": False, "error": str(exc)[:300], "certs": []}
