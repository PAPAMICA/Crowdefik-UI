import json as _json
import math
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import get_db, slot_fmt_sql
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
    limit: int = 10,
    scenario: str | None = None,
    target_host: str | None = None,
) -> dict[str, Any]:
    """All stored alerts for a specific attacker IP, paginated + filterable."""
    limit = max(1, min(limit, 200))
    q = (
        db.query(StoredAlert)
        .filter(StoredAlert.source_ip == ip)
        .order_by(StoredAlert.start_at.desc())
    )
    if scenario:
        q = q.filter(StoredAlert.scenario.ilike(f"%{scenario}%"))
    if target_host:
        q = q.filter(StoredAlert.target_host.ilike(f"%{target_host}%"))
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
    page: int = 1,
    limit: int = 10,
    type_filter: str | None = None,
) -> dict[str, Any]:
    """All stored decisions for a specific IP, paginated + filterable."""
    limit = max(1, min(limit, 200))
    q = (
        db.query(StoredDecision)
        .filter(StoredDecision.ip_value == ip)
        .order_by(StoredDecision.synced_at.desc())
    )
    if type_filter:
        q = q.filter(StoredDecision.decision_type.ilike(f"%{type_filter}%"))
    total = q.count()
    rows = q.offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total,
        "page": page,
        "pages": math.ceil(total / limit) if total else 0,
        "decisions": [
            {
                "id": r.id,
                "type": r.decision_type,
                "scenario": r.scenario,
                "duration": r.duration_str,
                "until": r.until.isoformat() if r.until else None,
                "synced_at": r.synced_at.isoformat() if r.synced_at else None,
            }
            for r in rows
        ],
    }


@router.get("/{ip}/requests")
def get_ip_requests(
    ip: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    page: int = 1,
    limit: int = 10,
    method: str | None = None,
    status: str | None = None,
    path_filter: str | None = None,
) -> dict[str, Any]:
    """HTTP requests from a specific IP parsed from the Traefik access log."""
    import json as _json
    import subprocess
    import shlex
    from pathlib import Path

    from app.settings import get_settings
    from app.api.logs_api import _resolve_path

    s = get_settings()
    log_path = _resolve_path(db, "log_path_access", s.traefik_log_path)
    if not log_path or not log_path.exists():
        return {"available": False, "total": 0, "page": 1, "pages": 0, "entries": []}

    limit = max(1, min(limit, 200))

    # Grep for IP in log file (fast pre-filter)
    quoted = shlex.quote(str(log_path))
    pipeline = f"grep -a {shlex.quote(ip)} {quoted} | tail -n 5000"
    try:
        result = subprocess.run(["sh", "-c", pipeline], capture_output=True, text=True, timeout=30)
        raw_lines = result.stdout.splitlines()
    except Exception:
        raw_lines = []

    entries: list[dict[str, Any]] = []
    method_lc = method.lower() if method else None
    path_lc = path_filter.lower() if path_filter else None

    for line in reversed(raw_lines):
        try:
            e = _json.loads(line)
        except Exception:
            continue

        client = (e.get("ClientHost") or (e.get("ClientAddr") or "").split(":")[0])
        if client != ip:
            continue

        req_method = e.get("RequestMethod", "")
        req_path = e.get("RequestPath") or e.get("RequestURI", "")
        code = e.get("DownstreamStatus") or e.get("OriginStatus")
        host = (e.get("RequestHost") or "").lower().split(":")[0]
        time_str = e.get("StartUTC") or e.get("time") or ""

        if method_lc and req_method.lower() != method_lc:
            continue
        if path_lc and path_lc not in req_path.lower():
            continue
        if status:
            cat = str(code)[0] + "xx" if code else ""
            if status != cat and str(code) != status:
                continue

        entries.append({
            "time": time_str,
            "host": host,
            "method": req_method,
            "path": req_path,
            "status": code,
            "duration_ms": round((e.get("Duration") or 0) / 1_000_000, 1),
            "bytes": e.get("DownstreamContentSize"),
            "router": e.get("RouterName"),
            "user_agent": e.get("request_User-Agent") or e.get("RequestUserAgent"),
        })

    total = len(entries)
    pages = math.ceil(total / limit) if total else 0
    paged = entries[(page - 1) * limit: page * limit]
    return {"available": True, "total": total, "page": page, "pages": pages, "entries": paged}


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
            slot_fmt_sql('%Y-%m-%d', StoredAlert.synced_at).label('day'),
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
