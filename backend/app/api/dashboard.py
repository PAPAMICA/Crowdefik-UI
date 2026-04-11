from datetime import date, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import allowed_router_names, get_current_user
from app.core import cache as cache_mod
from app.db import get_db
from app.integrations import traefik_client
from app.models import IpGeoCache, StoredAlert, StoredDecision, User
from app.services.routers_view import build_router_rows, filter_rows_for_user
from app.services.scope_filter import hosts_from_rules

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

SUMMARY_DAYS = 7


def _visible_rows(db: Session, user: User):
    def traefik_factory():
        return traefik_client.fetch_routers_sync(db)

    raw_routers = cache_mod.get_cached("traefik:routers", traefik_factory)
    rows = build_router_rows(raw_routers)
    allowed = allowed_router_names(db, user)
    return filter_rows_for_user(rows, is_superuser=user.is_superuser, allowed_routers=allowed)


def compute_dashboard_summary(db: Session, user: User) -> dict[str, Any]:
    """Build dashboard summary entirely from the local DB — no LAPI round-trip."""
    rows_visible = _visible_rows(db, user)
    protected = sum(1 for r in rows_visible if r["crowdsec_effective"])

    cutoff = datetime.utcnow() - timedelta(days=SUMMARY_DAYS)
    hosts: set[str] | None = None
    if not user.is_superuser:
        hosts = hosts_from_rules(rows_visible)

    # Alerts count (rolling 7 days)
    alert_q = db.query(StoredAlert).filter(StoredAlert.synced_at >= cutoff)
    if hosts is not None:
        alert_q = alert_q.filter(StoredAlert.target_host.in_(hosts))
    alerts_count = alert_q.count()

    # Decisions count (current snapshot in DB)
    decisions_count = db.query(StoredDecision).count()

    # Top attacker IPs by alert frequency
    top_ip_q = (
        db.query(StoredAlert.source_ip, func.count(StoredAlert.id).label("cnt"))
        .filter(StoredAlert.synced_at >= cutoff, StoredAlert.source_ip.isnot(None))
        .group_by(StoredAlert.source_ip)
        .order_by(func.count(StoredAlert.id).desc())
        .limit(10)
    )
    if hosts is not None:
        top_ip_q = top_ip_q.filter(StoredAlert.target_host.in_(hosts))
    top_ip_rows = top_ip_q.all()

    ip_list = [r.source_ip for r in top_ip_rows]
    geo_map = {r.ip: r for r in db.query(IpGeoCache).filter(IpGeoCache.ip.in_(ip_list)).all()}
    top_ips = [
        {
            "ip": r.source_ip,
            "count": r.cnt,
            "country_code": geo_map[r.source_ip].country_code if r.source_ip in geo_map else None,
            "country": geo_map[r.source_ip].country if r.source_ip in geo_map else None,
        }
        for r in top_ip_rows
    ]

    # Attack type breakdown
    sc_q = (
        db.query(StoredAlert.scenario, func.count(StoredAlert.id).label("cnt"))
        .filter(StoredAlert.synced_at >= cutoff, StoredAlert.scenario != "")
        .group_by(StoredAlert.scenario)
        .order_by(func.count(StoredAlert.id).desc())
        .limit(12)
    )
    if hosts is not None:
        sc_q = sc_q.filter(StoredAlert.target_host.in_(hosts))

    return {
        "routers_total": len(rows_visible),
        "routers_crowdsec_effective": protected,
        "decisions_count": decisions_count,
        "alerts_count": alerts_count,
        "top_attacker_ips": top_ips,
        "attack_types": [{"type": r.scenario, "count": r.cnt} for r in sc_q.all()],
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
    days: int = 7,
) -> list[dict[str, Any]]:
    """Alert + blocked-IP counts per slot (hourly for 1 day, daily otherwise)."""
    days = max(1, min(days, 90))
    hourly = days == 1
    now = datetime.utcnow()

    # Build per-user host filter
    hosts: set[str] | None = None
    if not user.is_superuser:
        allowed = allowed_router_names(db, user)
        raw_r = cache_mod.get_cached("traefik:routers", lambda: traefik_client.fetch_routers_sync(db))
        rows_v = filter_rows_for_user(build_router_rows(raw_r), is_superuser=False, allowed_routers=allowed)
        hosts = hosts_from_rules(rows_v)

    result = []
    slots = 24 if hourly else days
    for i in range(slots - 1, -1, -1):
        if hourly:
            start = (now - timedelta(hours=i + 1)).replace(minute=0, second=0, microsecond=0)
            end = start + timedelta(hours=1)
            label = start.strftime("%H:%M")
        else:
            d = date.today() - timedelta(days=i)
            start = datetime(d.year, d.month, d.day, 0, 0, 0)
            end = start + timedelta(days=1)
            label = d.isoformat()

        aq = db.query(StoredAlert).filter(StoredAlert.synced_at >= start, StoredAlert.synced_at < end)
        dq = db.query(StoredDecision).filter(StoredDecision.synced_at >= start, StoredDecision.synced_at < end)
        if hosts:
            aq = aq.filter(StoredAlert.source_ip.in_(list(hosts)))
            dq = dq.filter(StoredDecision.ip_value.in_(list(hosts)))

        result.append({"date": label, "alerts": aq.count(), "blocked": dq.count()})
    return result


@router.get("/geo")
def geo_points(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    days: int = 7,
) -> list[dict[str, Any]]:
    """Geolocated attacker IPs from stored alerts (last N days)."""
    days = max(1, min(days, 90))
    cutoff = datetime.utcnow() - timedelta(days=days)
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


@router.get("/service-stats")
def service_stats(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    days: int = 7,
) -> dict[str, Any]:
    """
    Per-service breakdown of alerts (last N days) and correlated decisions.
    Uses target_host extracted from CrowdSec alert events' http_host metadata.
    """
    days = max(1, min(days, 90))
    cutoff = datetime.utcnow() - timedelta(days=days)

    # ── Alerts per service ───────────────────────────────────
    alert_q = (
        db.query(StoredAlert.target_host, func.count(StoredAlert.id).label("alert_count"))
        .filter(StoredAlert.synced_at >= cutoff, StoredAlert.target_host.isnot(None))
        .group_by(StoredAlert.target_host)
    )

    if not user.is_superuser:
        allowed = allowed_router_names(db, user)
        raw_r = cache_mod.get_cached("traefik:routers", lambda: traefik_client.fetch_routers_sync(db))
        from app.services.routers_view import build_router_rows, filter_rows_for_user
        rows_v = filter_rows_for_user(build_router_rows(raw_r), is_superuser=False, allowed_routers=allowed)
        from app.services.scope_filter import hosts_from_rules
        hosts = hosts_from_rules(rows_v)
        if hosts:
            alert_q = alert_q.filter(StoredAlert.target_host.in_(list(hosts)))

    alerts_by_service = [
        {"host": host or "unknown", "alert_count": count, "favicon": f"https://icons.duckduckgo.com/ip3/{host}.ico" if host else None}
        for host, count in alert_q.order_by(func.count(StoredAlert.id).desc()).limit(20).all()
    ]

    # ── Unique attacker IPs per service ──────────────────────
    ip_q = (
        db.query(StoredAlert.target_host, func.count(func.distinct(StoredAlert.source_ip)).label("ip_count"))
        .filter(StoredAlert.synced_at >= cutoff, StoredAlert.target_host.isnot(None), StoredAlert.source_ip.isnot(None))
        .group_by(StoredAlert.target_host)
        .all()
    )
    ip_map = {host: count for host, count in ip_q}

    for s in alerts_by_service:
        s["unique_ips"] = ip_map.get(s["host"], 0)

    return {"by_service": alerts_by_service}


@router.post("/sync")
def trigger_sync(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Manually trigger a CrowdSec → DB sync."""
    from app.services.sync_service import run_full_sync
    return run_full_sync(db)
