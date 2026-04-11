"""
Service-level dashboard API.

Provides per-virtual-host statistics and recent Traefik request logs so the
frontend can render a full security dashboard for any target service.
"""
import json
import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import get_db
from app.models import IpGeoCache, StoredAlert, StoredDecision, User
from app.settings import get_settings

router = APIRouter(prefix="/services", tags=["services"])
log = logging.getLogger(__name__)


# ── helpers ──────────────────────────────────────────────────────────────────

def _require_host(host: str) -> str:
    host = host.strip().lower()
    if not host or len(host) > 253:
        raise HTTPException(status_code=400, detail="Invalid host")
    return host


def _geo_map(db: Session, ips: list[str]) -> dict[str, IpGeoCache]:
    if not ips:
        return {}
    return {r.ip: r for r in db.query(IpGeoCache).filter(IpGeoCache.ip.in_(ips)).all()}


# ── endpoints ─────────────────────────────────────────────────────────────────

@router.get("/{host}/overview")
def service_overview(
    host: str,
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    days: int = 7,
) -> dict[str, Any]:
    """
    Full security overview for a single virtual host (target service).

    Returns:
    - summary stats (alerts, unique IPs, blocked decisions, events)
    - alerts timeline (per day)
    - top attacker IPs (with geo)
    - top attack scenarios
    - recent alerts list
    """
    host = _require_host(host)
    days = max(1, min(days, 90))
    cutoff = datetime.utcnow() - timedelta(days=days)

    # ── base query ────────────────────────────────────────────────────────────
    base_q = db.query(StoredAlert).filter(
        StoredAlert.target_host == host,
        StoredAlert.synced_at >= cutoff,
    )

    total_alerts = base_q.count()
    unique_ips: int = (
        db.query(func.count(func.distinct(StoredAlert.source_ip)))
        .filter(StoredAlert.target_host == host, StoredAlert.synced_at >= cutoff, StoredAlert.source_ip.isnot(None))
        .scalar() or 0
    )
    total_events: int = (
        db.query(func.coalesce(func.sum(StoredAlert.events_count), 0))
        .filter(StoredAlert.target_host == host, StoredAlert.synced_at >= cutoff)
        .scalar() or 0
    )

    # ── timeline (hourly for 1 day, daily otherwise) ──────────────────────────
    from datetime import date as date_type
    hourly = days == 1
    now = datetime.utcnow()
    slots = 24 if hourly else days

    # Pre-compute all attacker IPs for this service (used for blocked curve)
    attacker_ips = {
        row.source_ip
        for row in db.query(StoredAlert.source_ip)
        .filter(StoredAlert.target_host == host, StoredAlert.synced_at >= cutoff, StoredAlert.source_ip.isnot(None))
        .distinct()
        .all()
        if row.source_ip
    }

    timeline = []
    for i in range(slots - 1, -1, -1):
        if hourly:
            slot_start = (now - timedelta(hours=i + 1)).replace(minute=0, second=0, microsecond=0)
            slot_end = slot_start + timedelta(hours=1)
            label = slot_start.strftime("%H:%M")
        else:
            d = date_type.today() - timedelta(days=i)
            slot_start = datetime(d.year, d.month, d.day)
            slot_end = slot_start + timedelta(days=1)
            label = d.isoformat()

        alerts_in_slot = (
            db.query(StoredAlert)
            .filter(StoredAlert.target_host == host, StoredAlert.synced_at >= slot_start, StoredAlert.synced_at < slot_end)
            .count()
        )
        blocked_in_slot = 0
        if attacker_ips:
            blocked_in_slot = (
                db.query(StoredDecision)
                .filter(
                    StoredDecision.ip_value.in_(attacker_ips),
                    StoredDecision.synced_at >= slot_start,
                    StoredDecision.synced_at < slot_end,
                )
                .count()
            )
        timeline.append({"date": label, "alerts": alerts_in_slot, "blocked": blocked_in_slot})

    # ── top attacker IPs ──────────────────────────────────────────────────────
    ip_counts = (
        db.query(StoredAlert.source_ip, func.count(StoredAlert.id).label("cnt"))
        .filter(StoredAlert.target_host == host, StoredAlert.synced_at >= cutoff, StoredAlert.source_ip.isnot(None))
        .group_by(StoredAlert.source_ip)
        .order_by(func.count(StoredAlert.id).desc())
        .limit(10)
        .all()
    )
    ip_list = [row.source_ip for row in ip_counts]
    geo = _geo_map(db, ip_list)
    top_ips = [
        {
            "ip": row.source_ip,
            "count": row.cnt,
            "country_code": geo[row.source_ip].country_code if row.source_ip in geo else None,
            "country": geo[row.source_ip].country if row.source_ip in geo else None,
            "city": geo[row.source_ip].city if row.source_ip in geo else None,
            "isp": geo[row.source_ip].isp if row.source_ip in geo else None,
        }
        for row in ip_counts
    ]

    # ── top scenarios ─────────────────────────────────────────────────────────
    scenario_counts = (
        db.query(StoredAlert.scenario, func.count(StoredAlert.id).label("cnt"))
        .filter(StoredAlert.target_host == host, StoredAlert.synced_at >= cutoff)
        .group_by(StoredAlert.scenario)
        .order_by(func.count(StoredAlert.id).desc())
        .limit(10)
        .all()
    )
    top_scenarios = [{"scenario": row.scenario, "count": row.cnt} for row in scenario_counts]

    # ── recent alerts ─────────────────────────────────────────────────────────
    recent_rows = (
        base_q.order_by(StoredAlert.start_at.desc()).limit(50).all()
    )
    # Enrich with raw context from stored JSON
    recent_alerts = []
    for row in recent_rows:
        try:
            raw = json.loads(row.raw_json)
        except Exception:
            raw = {}
        context = {c["key"]: c["value"] for c in (raw.get("context") or []) if isinstance(c, dict) and c.get("key")}
        recent_alerts.append({
            "id": row.id,
            "scenario": row.scenario,
            "source_ip": row.source_ip,
            "country": row.source_country,
            "events_count": row.events_count,
            "start_at": row.start_at.isoformat() if row.start_at else None,
            "stop_at": row.stop_at.isoformat() if row.stop_at else None,
            "context": context,
        })

    # ── blocked decisions for IPs that targeted this host ────────────────────
    blocked_count = 0
    if ip_list:
        blocked_count = (
            db.query(StoredDecision)
            .filter(StoredDecision.ip_value.in_(ip_list))
            .count()
        )

    return {
        "host": host,
        "days": days,
        "stats": {
            "total_alerts": total_alerts,
            "unique_ips": unique_ips,
            "blocked_decisions": blocked_count,
            "total_events": total_events,
        },
        "timeline": timeline,
        "top_ips": top_ips,
        "top_scenarios": top_scenarios,
        "recent_alerts": recent_alerts,
    }


@router.get("/{host}/logs")
def service_logs(
    host: str,
    _db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    limit: int = 200,
) -> dict[str, Any]:
    """
    Recent Traefik access.log entries for a given virtual host.

    Requires CROWDEFIK_TRAEFIK_LOG_PATH to be configured and the log file
    to be mounted inside the container.  Returns an empty list gracefully
    if logs are not available.
    """
    host = _require_host(host)
    limit = max(1, min(limit, 1000))

    log_path = get_settings().traefik_log_path
    if not log_path or not log_path.exists():
        return {"host": host, "available": False, "entries": []}

    try:
        from app.integrations.traefik_log_reader import _tail_file
        import json as _json

        raw_lines = _tail_file(log_path, 100_000)
        entries = []
        for line in reversed(raw_lines):
            if len(entries) >= limit:
                break
            try:
                entry = _json.loads(line)
            except _json.JSONDecodeError:
                continue
            # Strip optional port (e.g. "example.com:443" → "example.com")
            entry_host = (entry.get("RequestHost") or entry.get("RequestAddr") or "").lower().split(":")[0].strip()
            if entry_host != host:
                continue
            entries.append({
                "time": entry.get("StartUTC") or entry.get("time"),
                "method": entry.get("RequestMethod"),
                "path": entry.get("RequestPath") or entry.get("RequestURI"),
                "status": entry.get("DownstreamStatus") or entry.get("OriginStatus"),
                "client_ip": entry.get("ClientHost") or (entry.get("ClientAddr") or "").split(":")[0],
                "duration_ms": round((entry.get("Duration") or 0) / 1_000_000, 1),
                "router": entry.get("RouterName"),
                "service": entry.get("ServiceName"),
                "tls_version": entry.get("TLSVersion"),
                "bytes": entry.get("DownstreamContentSize"),
            })

        return {"host": host, "available": True, "entries": entries}

    except Exception as exc:
        log.warning("Failed to read Traefik logs for host %s: %s", host, exc)
        return {"host": host, "available": False, "entries": []}
