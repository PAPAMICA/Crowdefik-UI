"""
Sync CrowdSec LAPI data (alerts + decisions) into local SQLite.
Runs at startup and every 5 minutes in background.
Keeps only the last 7 days of data.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.integrations import crowdsec_client, ipgeo_client
from app.models import IpGeoCache, StoredAlert, StoredDecision

log = logging.getLogger(__name__)

RETENTION_DAYS = 7


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        s = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(s).replace(tzinfo=None)
    except Exception:
        return None


def sync_alerts(db: Session, alerts: list[dict]) -> int:
    """Upsert alerts. Returns count of new rows inserted."""
    now = datetime.utcnow()
    inserted = 0
    for a in alerts:
        alert_id = a.get("id")
        if not isinstance(alert_id, int):
            continue
        if db.get(StoredAlert, alert_id):
            continue
        src = a.get("source") or {}
        lat = src.get("latitude")
        lon = src.get("longitude")
        row = StoredAlert(
            id=alert_id,
            scenario=str(a.get("scenario") or ""),
            source_ip=str(src.get("ip") or src.get("value") or "") or None,
            source_country=str(src.get("cn") or "") or None,
            source_lat=float(lat) if lat is not None else None,
            source_lon=float(lon) if lon is not None else None,
            events_count=int(a.get("events_count") or 1),
            start_at=_parse_dt(a.get("start_at")),
            stop_at=_parse_dt(a.get("stop_at")),
            raw_json=json.dumps(a),
            synced_at=now,
        )
        db.add(row)
        inserted += 1
    if inserted:
        db.commit()
    return inserted


def sync_decisions(db: Session, decisions: list[dict]) -> int:
    now = datetime.utcnow()
    inserted = 0
    for d in decisions:
        decision_id = d.get("id")
        if not isinstance(decision_id, int):
            continue
        if db.get(StoredDecision, decision_id):
            continue
        row = StoredDecision(
            id=decision_id,
            ip_value=str(d.get("value") or d.get("ip") or ""),
            decision_type=str(d.get("type") or ""),
            scope=str(d.get("scope") or ""),
            scenario=str(d.get("scenario") or ""),
            duration_str=str(d.get("duration") or ""),
            until=_parse_dt(d.get("until")),
            raw_json=json.dumps(d),
            synced_at=now,
        )
        db.add(row)
        inserted += 1
    if inserted:
        db.commit()
    return inserted


def enrich_geo(db: Session, batch_size: int = 50) -> int:
    """Geolocate stored alerts whose IPs have no lat/lon yet, using ip_geo_cache."""
    # IPs in stored_alerts that have no geo data and are not already in cache
    unknown_ips: list[str] = (
        db.query(StoredAlert.source_ip)
        .filter(
            StoredAlert.source_ip.isnot(None),
            StoredAlert.source_lat.is_(None),
        )
        .distinct()
        .limit(batch_size * 3)
        .all()
    )
    unique = list({r[0] for r in unknown_ips if r[0]})
    if not unique:
        return 0

    # Check which are already in geo cache
    cached = {r.ip for r in db.query(IpGeoCache.ip).filter(IpGeoCache.ip.in_(unique)).all()}
    to_lookup = [ip for ip in unique if ip not in cached][:batch_size]

    if not to_lookup:
        # Apply cached geo to stored alerts that lack it
        _apply_cached_geo(db, unique)
        return 0

    results = ipgeo_client.batch_geolocate(to_lookup)
    count = 0
    for g in results:
        ip = g.get("query", "")
        if not ip:
            continue
        cache_row = IpGeoCache(
            ip=ip,
            lat=float(g["lat"]) if g.get("lat") is not None else None,
            lon=float(g["lon"]) if g.get("lon") is not None else None,
            country_code=g.get("countryCode"),
            country=g.get("country"),
            city=g.get("city"),
            isp=g.get("isp"),
            updated_at=datetime.utcnow(),
        )
        db.merge(cache_row)
        count += 1
    if count:
        db.commit()

    _apply_cached_geo(db, to_lookup)
    return count


def _apply_cached_geo(db: Session, ips: list[str]) -> None:
    """Back-fill lat/lon from geo cache into stored_alerts rows."""
    if not ips:
        return
    geo_map: dict[str, IpGeoCache] = {
        r.ip: r for r in db.query(IpGeoCache).filter(IpGeoCache.ip.in_(ips)).all()
    }
    rows = (
        db.query(StoredAlert)
        .filter(StoredAlert.source_ip.in_(ips), StoredAlert.source_lat.is_(None))
        .all()
    )
    for row in rows:
        geo = geo_map.get(row.source_ip or "")
        if geo and geo.lat is not None:
            row.source_lat = geo.lat
            row.source_lon = geo.lon
            row.source_country = row.source_country or geo.country_code
    if rows:
        db.commit()


def cleanup_old(db: Session) -> int:
    cutoff = datetime.utcnow() - timedelta(days=RETENTION_DAYS)
    n_a = db.query(StoredAlert).filter(StoredAlert.synced_at < cutoff).delete()
    n_d = db.query(StoredDecision).filter(StoredDecision.synced_at < cutoff).delete()
    db.commit()
    return n_a + n_d


def run_full_sync(db: Session) -> dict:
    """Fetch from CrowdSec, store in DB, enrich geo, cleanup old. Safe to call repeatedly."""
    alerts_raw = crowdsec_client.fetch_alerts_sync(db)
    decisions_raw = crowdsec_client.fetch_decisions_sync(db)

    new_alerts = sync_alerts(db, alerts_raw)
    new_decisions = sync_decisions(db, decisions_raw)
    geo_enriched = enrich_geo(db)
    cleaned = cleanup_old(db)

    log.info("Sync done: +%d alerts, +%d decisions, %d IPs geolocated, %d old rows removed",
             new_alerts, new_decisions, geo_enriched, cleaned)
    return {
        "new_alerts": new_alerts,
        "new_decisions": new_decisions,
        "geo_enriched": geo_enriched,
        "cleaned": cleaned,
    }
