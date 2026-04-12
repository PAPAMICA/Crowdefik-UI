"""
Global search — IPs (from decisions/alerts) + services (from Traefik router cache).
Used by the sidebar search bar with autocomplete.
"""
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import allowed_router_names, get_current_user
from app.core import cache as cache_mod
from app.db import get_db
from app.integrations import traefik_client
from app.models import IpGeoCache, StoredAlert, StoredDecision, User
from app.services.routers_view import build_router_rows, filter_rows_for_user
from app.services.scope_filter import hosts_from_rules

router = APIRouter(prefix="/search", tags=["search"])

import re as _re

_HOST_RE = _re.compile(r'Host\(`([^`]+)`\)', _re.IGNORECASE)


def _host_from_rule(rule: str) -> str | None:
    m = _HOST_RE.search(rule or "")
    return m.group(1) if m else None


@router.get("")
def global_search(
    q: Annotated[str, Query(min_length=1, max_length=100)],
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    limit: int = 8,
) -> dict[str, Any]:
    """
    Search IPs (from stored decisions/alerts) and services (from Traefik routers).
    Returns up to `limit` results per category.
    """
    q = q.strip()
    if len(q) < 1:
        return {"ips": [], "services": []}

    limit = max(1, min(limit, 20))
    ql = f"%{q.lower()}%"

    # ── IPs from decisions ────────────────────────────────────────────────────
    dec_ips = (
        db.query(StoredDecision.ip_value, func.count(StoredDecision.id).label("n"))
        .filter(StoredDecision.ip_value.ilike(ql))
        .group_by(StoredDecision.ip_value)
        .order_by(func.count(StoredDecision.id).desc())
        .limit(limit)
        .all()
    )
    # IPs from alerts (may not have a decision)
    alert_ips = (
        db.query(StoredAlert.source_ip, func.count(StoredAlert.id).label("n"))
        .filter(StoredAlert.source_ip.isnot(None), StoredAlert.source_ip.ilike(ql))
        .group_by(StoredAlert.source_ip)
        .order_by(func.count(StoredAlert.id).desc())
        .limit(limit)
        .all()
    )

    # Merge, deduplicate, prefer decision entries
    ip_map: dict[str, dict[str, Any]] = {}
    for ip, n in dec_ips:
        if ip:
            ip_map[ip] = {"ip": ip, "decisions": n, "alerts": 0, "is_banned": True}
    for ip, n in alert_ips:
        if ip:
            if ip in ip_map:
                ip_map[ip]["alerts"] = n
            else:
                ip_map[ip] = {"ip": ip, "decisions": 0, "alerts": n, "is_banned": False}

    # Enrich with geo cache
    geo_map = {
        r.ip: r
        for r in db.query(IpGeoCache)
        .filter(IpGeoCache.ip.in_(list(ip_map.keys())))
        .all()
    }
    for ip, entry in ip_map.items():
        geo = geo_map.get(ip)
        entry["country_code"] = geo.country_code if geo else None
        entry["country"] = geo.country if geo else None

    # Sort: banned first, then by total activity
    ip_results = sorted(
        ip_map.values(),
        key=lambda x: (not x["is_banned"], -(x["decisions"] + x["alerts"])),
    )[:limit]

    # ── Services from Traefik router cache ────────────────────────────────────
    try:
        raw_routers = cache_mod.get_cached(
            "traefik:routers", lambda: traefik_client.fetch_routers_sync(db)
        )
    except Exception:
        raw_routers = []

    rows = build_router_rows(raw_routers)
    allowed = allowed_router_names(db, user)
    rows_visible = filter_rows_for_user(
        rows, is_superuser=user.is_superuser, allowed_routers=allowed
    )

    ql_plain = q.lower()
    service_results: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    for r in rows_visible:
        rule = str(r.get("rule") or "")
        name = str(r.get("name") or "")
        host = _host_from_rule(rule) or ""
        if (
            ql_plain in host.lower()
            or ql_plain in name.lower()
            or ql_plain in rule.lower()
        ) and host and host not in seen_hosts:
            seen_hosts.add(host)
            service_results.append({
                "host": host,
                "router_name": name,
                "favicon": f"https://icons.duckduckgo.com/ip3/{host}.ico",
                "crowdsec": r.get("crowdsec_effective", False),
            })
            if len(service_results) >= limit:
                break

    return {"ips": ip_results, "services": service_results}
