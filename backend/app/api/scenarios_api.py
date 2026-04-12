"""
Scenarios API — attack-type statistics from stored alerts.

GET /api/scenarios            — list all unique scenarios with aggregate stats
GET /api/scenarios/{name}     — detail: timeline, top IPs, top targets, recent alerts
"""
import math
from datetime import datetime, date, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import get_db, slot_fmt_sql
from app.models import IpGeoCache, StoredAlert, User

router = APIRouter(prefix="/scenarios", tags=["scenarios"])


# ── List ───────────────────────────────────────────────────────────────────────

@router.get("")
def list_scenarios(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return all unique scenarios with alert count, top IP, top target, last seen."""
    limit = max(1, min(limit, 500))

    rows = (
        db.query(
            StoredAlert.scenario,
            func.count(StoredAlert.id).label("alert_count"),
            func.sum(StoredAlert.events_count).label("events_total"),
            func.max(StoredAlert.start_at).label("last_seen"),
            func.min(StoredAlert.start_at).label("first_seen"),
        )
        .filter(StoredAlert.scenario.isnot(None))
        .group_by(StoredAlert.scenario)
        .order_by(func.count(StoredAlert.id).desc())
        .limit(limit)
        .all()
    )

    result = []
    for r in rows:
        # Top IP for this scenario
        top_ip_row = (
            db.query(StoredAlert.source_ip, func.count(StoredAlert.id).label("n"))
            .filter(StoredAlert.scenario == r.scenario, StoredAlert.source_ip.isnot(None))
            .group_by(StoredAlert.source_ip)
            .order_by(func.count(StoredAlert.id).desc())
            .first()
        )
        # Top target for this scenario
        top_target_row = (
            db.query(StoredAlert.target_host, func.count(StoredAlert.id).label("n"))
            .filter(StoredAlert.scenario == r.scenario, StoredAlert.target_host.isnot(None))
            .group_by(StoredAlert.target_host)
            .order_by(func.count(StoredAlert.id).desc())
            .first()
        )
        # Distinct IPs
        distinct_ips = (
            db.query(func.count(func.distinct(StoredAlert.source_ip)))
            .filter(StoredAlert.scenario == r.scenario)
            .scalar() or 0
        )

        result.append({
            "scenario": r.scenario,
            "alert_count": r.alert_count,
            "events_total": int(r.events_total or 0),
            "distinct_ips": distinct_ips,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "top_ip": top_ip_row.source_ip if top_ip_row else None,
            "top_target": top_target_row.target_host if top_target_row else None,
        })

    return result


# ── Detail ─────────────────────────────────────────────────────────────────────

@router.get("/{scenario:path}")
def get_scenario(
    scenario: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    days: int = 30,
    top_limit: int = 10,
) -> dict[str, Any]:
    """Detailed stats for a specific scenario."""
    days = max(1, min(days, 90))
    top_limit = max(1, min(top_limit, 50))
    cutoff = datetime.utcnow() - timedelta(days=days)

    base_q = db.query(StoredAlert).filter(StoredAlert.scenario == scenario)
    total_alerts = base_q.count()
    events_total = db.query(func.sum(StoredAlert.events_count)).filter(StoredAlert.scenario == scenario).scalar() or 0

    # Timeline (daily)
    timeline_rows = (
        db.query(
            slot_fmt_sql('%Y-%m-%d', StoredAlert.synced_at).label('day'),
            func.count(StoredAlert.id).label('cnt'),
        )
        .filter(StoredAlert.scenario == scenario, StoredAlert.synced_at >= cutoff)
        .group_by('day')
        .all()
    )
    day_map = {r.day: r.cnt for r in timeline_rows}
    timeline = []
    for i in range(days - 1, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).date()
        key = d.isoformat()
        timeline.append({"date": key, "count": day_map.get(key, 0)})

    # Top attacker IPs (with geo)
    top_ip_rows = (
        db.query(StoredAlert.source_ip, func.count(StoredAlert.id).label("n"))
        .filter(StoredAlert.scenario == scenario, StoredAlert.source_ip.isnot(None))
        .group_by(StoredAlert.source_ip)
        .order_by(func.count(StoredAlert.id).desc())
        .limit(top_limit)
        .all()
    )
    top_ips_raw = [{"ip": r.source_ip, "count": r.n} for r in top_ip_rows]
    # Enrich with geo
    geo_map = {
        g.ip: g for g in db.query(IpGeoCache)
        .filter(IpGeoCache.ip.in_([x["ip"] for x in top_ips_raw]))
        .all()
    }
    top_ips = []
    for item in top_ips_raw:
        geo = geo_map.get(item["ip"])
        top_ips.append({
            **item,
            "country_code": geo.country_code if geo else None,
            "country": geo.country if geo else None,
            "abuse_score": geo.abuse_score if geo else None,
        })

    # Top targets
    top_targets = [
        {"host": r.target_host, "count": r.n}
        for r in (
            db.query(StoredAlert.target_host, func.count(StoredAlert.id).label("n"))
            .filter(StoredAlert.scenario == scenario, StoredAlert.target_host.isnot(None))
            .group_by(StoredAlert.target_host)
            .order_by(func.count(StoredAlert.id).desc())
            .limit(top_limit)
            .all()
        )
    ]

    # Recent alerts (last 20)
    recent_rows = (
        base_q.order_by(StoredAlert.start_at.desc()).limit(20).all()
    )
    recent_alerts = [
        {
            "id": a.id,
            "source_ip": a.source_ip,
            "target_host": a.target_host,
            "events_count": a.events_count,
            "start_at": a.start_at.isoformat() if a.start_at else None,
        }
        for a in recent_rows
    ]

    # Distinct IPs
    distinct_ips = (
        db.query(func.count(func.distinct(StoredAlert.source_ip)))
        .filter(StoredAlert.scenario == scenario)
        .scalar() or 0
    )

    first_seen = base_q.order_by(StoredAlert.start_at.asc()).with_entities(StoredAlert.start_at).first()
    last_seen = base_q.order_by(StoredAlert.start_at.desc()).with_entities(StoredAlert.start_at).first()

    return {
        "scenario": scenario,
        "total_alerts": total_alerts,
        "events_total": int(events_total),
        "distinct_ips": distinct_ips,
        "first_seen": first_seen[0].isoformat() if first_seen and first_seen[0] else None,
        "last_seen": last_seen[0].isoformat() if last_seen and last_seen[0] else None,
        "timeline": timeline,
        "top_ips": top_ips,
        "top_targets": top_targets,
        "recent_alerts": recent_alerts,
    }
