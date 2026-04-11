import json
from collections import Counter
from datetime import date, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import allowed_router_names, get_current_user
from app.core import cache as cache_mod
from app.db import get_db
from app.integrations import crowdsec_client, traefik_client
from app.models import StoredAlert, StoredDecision, User
from app.services.routers_view import build_router_rows, filter_rows_for_user
from app.services.scope_filter import blob_matches_hosts, hosts_from_rules
from app.settings import get_settings

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _top_ips(decisions: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    ips = [d.get("value") or d.get("ip") for d in decisions if (d.get("value") or d.get("ip"))]
    c = Counter([i for i in ips if isinstance(i, str)])
    return [{"ip": ip, "count": n} for ip, n in c.most_common(limit)]


def compute_dashboard_summary(db: Session, user: User) -> dict[str, Any]:
    s = get_settings()

    def traefik_factory():
        return traefik_client.fetch_routers_sync(db)

    raw_routers = cache_mod.get_cached("traefik:routers", traefik_factory)
    rows = build_router_rows(raw_routers)
    allowed = allowed_router_names(db, user)
    rows_visible = filter_rows_for_user(rows, is_superuser=user.is_superuser, allowed_routers=allowed)
    protected = sum(1 for r in rows_visible if r["crowdsec_effective"])

    def decisions_factory():
        return crowdsec_client.fetch_decisions_sync(db)

    def alerts_factory():
        return crowdsec_client.fetch_alerts_sync(db)

    decisions = cache_mod.get_cached("crowdsec:decisions", decisions_factory, ttl_seconds=s.crowdsec_cache_ttl_seconds)
    alerts = cache_mod.get_cached("crowdsec:alerts", alerts_factory, ttl_seconds=s.crowdsec_cache_ttl_seconds)

    if user.is_superuser:
        decisions_visible = decisions
        alerts_visible = alerts
    else:
        hosts = hosts_from_rules(rows_visible)
        decisions_visible = [d for d in decisions if blob_matches_hosts(d, hosts)]
        alerts_visible = [a for a in alerts if blob_matches_hosts(a, hosts)]

    scenario_counts: Counter[str] = Counter()
    for a in alerts_visible:
        if isinstance(a, dict):
            scen = a.get("scenario") or (a.get("labels", {}).get("scenario") if isinstance(a.get("labels"), dict) else None)
            if scen:
                scenario_counts[str(scen)] += 1

    return {
        "routers_total": len(rows_visible),
        "routers_crowdsec_effective": protected,
        "decisions_count": len(decisions_visible),
        "alerts_count": len(alerts_visible),
        "top_attacker_ips": _top_ips(decisions_visible),
        "attack_types": [{"type": k, "count": v} for k, v in scenario_counts.most_common(12)],
    }


@router.get("/summary")
def summary(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    return compute_dashboard_summary(db, user)


@router.get("/timeline")
def timeline(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Alert counts per day for the last 7 days (from stored DB data)."""
    today = date.today()
    result = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        start = datetime(day.year, day.month, day.day, 0, 0, 0)
        end = start + timedelta(days=1)
        q = db.query(StoredAlert).filter(
            StoredAlert.synced_at >= start,
            StoredAlert.synced_at < end,
        )
        if not user.is_superuser:
            allowed = allowed_router_names(db, user)
            raw_r = cache_mod.get_cached("traefik:routers", lambda: traefik_client.fetch_routers_sync(db))
            rows_v = filter_rows_for_user(build_router_rows(raw_r), is_superuser=False, allowed_routers=allowed)
            hosts = hosts_from_rules(rows_v)
            if hosts:
                q = q.filter(StoredAlert.source_ip.in_(list(hosts)))
        result.append({"date": day.isoformat(), "count": q.count()})
    return result


@router.get("/geo")
def geo_points(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Geolocated attacker IPs from stored alerts (last 7 days)."""
    cutoff = datetime.utcnow() - timedelta(days=7)
    q = db.query(StoredAlert).filter(
        StoredAlert.synced_at >= cutoff,
        StoredAlert.source_ip.isnot(None),
        StoredAlert.source_lat.isnot(None),
    )
    if not user.is_superuser:
        allowed = allowed_router_names(db, user)
        raw_r = cache_mod.get_cached("traefik:routers", lambda: traefik_client.fetch_routers_sync(db))
        rows_v = filter_rows_for_user(build_router_rows(raw_r), is_superuser=False, allowed_routers=allowed)
        hosts = hosts_from_rules(rows_v)
        if hosts:
            q = q.filter(StoredAlert.source_ip.in_(list(hosts)))

    alerts = q.all()

    points: dict[str, dict[str, Any]] = {}
    for a in alerts:
        ip = a.source_ip
        if not ip:
            continue
        if ip in points:
            points[ip]["count"] += 1
        else:
            points[ip] = {
                "ip": ip,
                "lat": a.source_lat,
                "lon": a.source_lon,
                "count": 1,
                "scenario": a.scenario or "",
                "country": a.source_country or "",
            }

    return sorted(points.values(), key=lambda x: x["count"], reverse=True)[:150]


@router.post("/sync")
def trigger_sync(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Manually trigger a CrowdSec → DB sync."""
    from app.services.sync_service import run_full_sync
    return run_full_sync(db)
