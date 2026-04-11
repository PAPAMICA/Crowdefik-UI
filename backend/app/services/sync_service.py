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


def _extract_target_host(alert: dict) -> str | None:
    """
    Extract the target HTTP host from a CrowdSec alert.
    Tries several locations used by different CrowdSec parsers:
     1. events[*].meta  key=http_host  (Traefik access log parser)
     2. context list    key=http_host  (AppSec WAF)
     3. context list    key=target_uri → absolute URL host
     4. alert.decisions[*].scope containing the host
    """
    # 1. Traefik-style: events[*].meta[key=http_host]
    events = alert.get("events") or []
    for event in events:
        meta = event.get("meta") or []
        for m in meta:
            if isinstance(m, dict):
                key = (m.get("key") or "").lower()
                if key in ("http_host", "http.host", "host"):
                    value = str(m.get("value") or "").strip()
                    if value:
                        return value.split(":")[0]  # strip port

    # 2 & 3. AppSec WAF context list
    context = alert.get("context") or []
    target_uri: str | None = None
    for c in context:
        if isinstance(c, dict):
            key = (c.get("key") or "").lower()
            value = str(c.get("value") or "").strip()
            if not value:
                continue
            if key in ("http_host", "http.host", "host"):
                return value.split(":")[0]
            if key == "target_uri":
                target_uri = value

    # 3b. If target_uri is an absolute URL, parse the host
    if target_uri:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target_uri)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass

    # 4. decisions[*].scope for host-scoped decisions
    for d in (alert.get("decisions") or []):
        scope = str(d.get("scope") or "").lower()
        value = str(d.get("value") or "").strip()
        if scope in ("host", "url") and value:
            try:
                from urllib.parse import urlparse
                h = urlparse(value).hostname or value
                if "." in h:
                    return h
            except Exception:
                if "." in value:
                    return value

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
            target_host=_extract_target_host(a),
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


def backfill_target_hosts(db: Session) -> int:
    """
    Backfill target_host for stored alerts that have none yet.

    Two passes:
    1. Fast path: re-parse raw_json (works for Traefik log-based alerts).
    2. Traefik log correlation: for WAF/AppSec direct alerts (kind=waf) whose
       context doesn't include the Host header, correlate by attacker IP +
       timestamp against the Traefik access.log.

    The flag `log_enrichment_attempted` is set to True after the second pass
    (success or failure) so we never re-read the log file for the same alert.
    """
    rows = db.query(StoredAlert).filter(StoredAlert.target_host.is_(None)).all()
    if not rows:
        return 0

    updated = 0
    # Alerts that still have no host after the fast pass AND haven't been
    # tried against the Traefik log yet.
    need_log_correlation: list[StoredAlert] = []

    for row in rows:
        try:
            data = json.loads(row.raw_json)
            host = _extract_target_host(data)
            if host:
                row.target_host = host
                updated += 1
            elif not row.log_enrichment_attempted:
                need_log_correlation.append(row)
        except Exception:
            if not row.log_enrichment_attempted:
                need_log_correlation.append(row)

    if updated:
        db.commit()

    if need_log_correlation:
        updated += _backfill_from_traefik_log(db, need_log_correlation)

    return updated


def _backfill_from_traefik_log(db: Session, rows: list[StoredAlert]) -> int:
    """
    Correlate WAF alerts (no target_host, not yet tried) against the Traefik
    access.log.  Always marks rows as attempted so this is called at most once
    per alert, regardless of whether a match is found.

    Requires CROWDEFIK_TRAEFIK_LOG_PATH to be set and the log file to be
    accessible inside the container (read-only volume mount).
    """
    from app.settings import get_settings
    from app.integrations.traefik_log_reader import LOOKBACK_HOURS

    log_path = get_settings().traefik_log_path

    # Restrict to alerts recent enough to potentially still be in the log.
    cutoff = datetime.utcnow() - timedelta(hours=LOOKBACK_HOURS)
    candidates = [r for r in rows if r.start_at and r.start_at >= cutoff]

    # Alerts older than the lookback window: mark attempted so they're never
    # retried (they'll never appear in the log again).
    too_old = [r for r in rows if r not in candidates]
    if too_old:
        for r in too_old:
            r.log_enrichment_attempted = True
        db.commit()

    if not candidates:
        return 0

    index: dict = {}
    if log_path:
        try:
            from app.integrations.traefik_log_reader import build_ip_host_index
            index = build_ip_host_index(log_path)
        except Exception as exc:
            log.warning("Traefik log correlation failed: %s", exc)

    updated = 0
    from app.integrations.traefik_log_reader import find_host_for_alert

    for row in candidates:
        # Mark as attempted regardless of outcome
        row.log_enrichment_attempted = True

        if not index or not row.source_ip or not row.start_at:
            continue

        # Extract target_uri from raw context for better path matching
        target_uri: str | None = None
        try:
            data = json.loads(row.raw_json)
            for c in (data.get("context") or []):
                if isinstance(c, dict) and c.get("key") == "target_uri":
                    target_uri = c.get("value")
                    break
        except Exception:
            pass

        host = find_host_for_alert(
            index,
            source_ip=row.source_ip,
            alert_time=row.start_at,
            target_uri=target_uri,
        )
        if host:
            row.target_host = host
            updated += 1

    db.commit()
    if updated:
        log.info("Traefik log correlation: enriched %d WAF alerts with target host", updated)

    return updated


def run_full_sync(db: Session) -> dict:
    """Fetch from CrowdSec, store in DB, enrich geo, cleanup old. Safe to call repeatedly."""
    alerts_raw = crowdsec_client.fetch_alerts_sync(db)
    decisions_raw = crowdsec_client.fetch_decisions_sync(db)

    new_alerts = sync_alerts(db, alerts_raw)
    new_decisions = sync_decisions(db, decisions_raw)
    geo_enriched = enrich_geo(db)
    backfill_target_hosts(db)
    cleaned = cleanup_old(db)

    log.info("Sync done: +%d alerts, +%d decisions, %d IPs geolocated, %d old rows removed",
             new_alerts, new_decisions, geo_enriched, cleaned)
    return {
        "new_alerts": new_alerts,
        "new_decisions": new_decisions,
        "geo_enriched": geo_enriched,
        "cleaned": cleaned,
    }
