import json as _json
import math
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import get_db
from app.integrations import abuseipdb_client, ipgeo_client
from app.models import IpGeoCache, StoredAlert, StoredDecision, User

router = APIRouter(prefix="/ip", tags=["ip"])

# Re-fetch abuse score after this many days (scores change over time).
_ABUSE_TTL_DAYS = 7
# Re-fetch geo after this many days (IPs rarely change region).
_GEO_TTL_DAYS = 30


def _geo_stale(row: IpGeoCache) -> bool:
    return (datetime.utcnow() - row.updated_at) > timedelta(days=_GEO_TTL_DAYS)


def _abuse_stale(row: IpGeoCache) -> bool:
    if row.abuse_updated_at is None:
        return True
    return (datetime.utcnow() - row.abuse_updated_at) > timedelta(days=_ABUSE_TTL_DAYS)


@router.get("/{ip}")
def get_ip_info(
    ip: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return geo + abuse data for *ip*.

    Strategy (fastest first):
      1. Read from IpGeoCache (DB).
      2. If geo is missing or stale (>30d), call ip-api.com and update cache.
      3. If abuse is missing or stale (>7d), call AbuseIPDB and update cache.
    External APIs are only called when the cached data is absent or expired.
    """
    row = db.query(IpGeoCache).filter(IpGeoCache.ip == ip).first()
    dirty = False

    # ── Geo ───────────────────────────────────────────────────────────────────
    if row is None or _geo_stale(row):
        geo_data = ipgeo_client.geolocate_ip(ip)
        if geo_data:
            if row is None:
                row = IpGeoCache(ip=ip)
            row.lat = geo_data.get("lat")
            row.lon = geo_data.get("lon")
            row.country_code = geo_data.get("countryCode")
            row.country = geo_data.get("country")
            row.city = geo_data.get("city")
            row.isp = geo_data.get("isp")
            row.updated_at = datetime.utcnow()
            dirty = True
        elif row is None:
            # geo failed and nothing cached — create a skeleton row so abuse can still be stored
            row = IpGeoCache(ip=ip, updated_at=datetime.utcnow())
            dirty = True

    geo: dict[str, Any] | None = None
    if row and (row.country or row.city):
        geo = {
            "country":     row.country,
            "countryCode": row.country_code,
            "city":        row.city,
            "isp":         row.isp,
            "lat":         row.lat,
            "lon":         row.lon,
        }

    # ── Abuse ─────────────────────────────────────────────────────────────────
    abuse: dict[str, Any] | None = None

    if row and not _abuse_stale(row) and row.abuse_score is not None:
        # Serve from cache — no external call needed
        abuse = {
            "abuseConfidenceScore": row.abuse_score,
            "totalReports":         row.abuse_total_reports,
            "isTor":                row.abuse_is_tor,
            "lastReportedAt":       row.abuse_last_reported_at,
            "domain":               row.abuse_domain,
            "countryCode":          row.country_code,
            "isp":                  row.isp,
        }
    else:
        # Cache miss or stale — call AbuseIPDB
        fresh = abuseipdb_client.check_ip(db, ip)
        if fresh:
            abuse = fresh
            if row is None:
                row = IpGeoCache(ip=ip, updated_at=datetime.utcnow())
            row.abuse_score          = fresh.get("abuseConfidenceScore")
            row.abuse_total_reports  = fresh.get("totalReports")
            row.abuse_is_tor         = fresh.get("isTor")
            row.abuse_last_reported_at = fresh.get("lastReportedAt")
            row.abuse_domain         = fresh.get("domain")
            row.abuse_updated_at     = datetime.utcnow()
            dirty = True

    # ── Persist ───────────────────────────────────────────────────────────────
    if dirty and row is not None:
        db.merge(row)
        db.commit()

    return {"ip": ip, "geo": geo, "abuse": abuse}


@router.get("/{ip}/alerts")
def get_ip_alerts(
    ip: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    page: int = 1,
    limit: int = 25,
) -> dict[str, Any]:
    """All stored alerts for a specific attacker IP, paginated."""
    limit = max(1, min(limit, 200))
    q = (
        db.query(StoredAlert)
        .filter(StoredAlert.source_ip == ip)
        .order_by(StoredAlert.start_at.desc())
    )
    total = q.count()
    rows = q.offset((page - 1) * limit).limit(limit).all()

    alerts = []
    for row in rows:
        try:
            a = _json.loads(row.raw_json)
        except Exception:
            a = {}
        alerts.append({
            "id": row.id,
            "scenario": row.scenario,
            "target_host": row.target_host,
            "events_count": row.events_count,
            "start_at": row.start_at.isoformat() if row.start_at else None,
            "stop_at": row.stop_at.isoformat() if row.stop_at else None,
            "context": a.get("context") or [],
        })

    return {
        "total": total,
        "page": page,
        "pages": math.ceil(total / limit) if total else 0,
        "alerts": alerts,
    }


@router.get("/{ip}/decisions")
def get_ip_decisions(
    ip: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """All stored decisions for a specific IP."""
    rows = (
        db.query(StoredDecision)
        .filter(StoredDecision.ip_value == ip)
        .order_by(StoredDecision.synced_at.desc())
        .limit(100)
        .all()
    )
    return [
        {
            "id": r.id,
            "type": r.decision_type,
            "scenario": r.scenario,
            "duration": r.duration_str,
            "until": r.until.isoformat() if r.until else None,
            "synced_at": r.synced_at.isoformat() if r.synced_at else None,
        }
        for r in rows
    ]


@router.get("/{ip}/timeline")
def get_ip_timeline(
    ip: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    days: int = 30,
) -> list[dict[str, Any]]:
    """Daily alert counts for this IP over the last N days."""
    from sqlalchemy import func
    from datetime import date

    days = max(1, min(days, 90))
    cutoff = datetime.utcnow() - timedelta(days=days)

    rows = (
        db.query(
            func.strftime('%Y-%m-%d', StoredAlert.synced_at).label('day'),
            func.count(StoredAlert.id).label('cnt'),
        )
        .filter(StoredAlert.source_ip == ip, StoredAlert.synced_at >= cutoff)
        .group_by('day')
        .all()
    )
    day_map = {r.day: r.cnt for r in rows}

    result = []
    for i in range(days - 1, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).date()
        key = d.isoformat()
        result.append({"date": key, "count": day_map.get(key, 0)})
    return result
