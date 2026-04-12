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

from app.api.allowlist_api import get_allowlisted_ips, is_ip_allowlisted
from app.integrations import crowdsec_client, ipgeo_client
from app.models import Allowlist, IpGeoCache, ServicePolicy, StoredAlert, StoredDecision

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
    if not alerts:
        return 0
    now = datetime.utcnow()

    # Pre-load all existing IDs in one query to eliminate N+1 SELECT per alert
    incoming_ids = [a["id"] for a in alerts if isinstance(a.get("id"), int)]
    existing_ids: set[int] = {
        r[0] for r in db.query(StoredAlert.id).filter(StoredAlert.id.in_(incoming_ids)).all()
    }

    inserted = 0
    for a in alerts:
        alert_id = a.get("id")
        if not isinstance(alert_id, int):
            continue
        if alert_id in existing_ids:
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
    if not decisions:
        return 0
    now = datetime.utcnow()

    # Pre-load all existing IDs in one query to eliminate N+1 SELECT per decision
    incoming_ids = [d["id"] for d in decisions if isinstance(d.get("id"), int)]
    existing_ids: set[int] = {
        r[0] for r in db.query(StoredDecision.id).filter(StoredDecision.id.in_(incoming_ids)).all()
    }

    inserted = 0
    for d in decisions:
        decision_id = d.get("id")
        if not isinstance(decision_id, int):
            continue
        if decision_id in existing_ids:
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

    Path resolution: DB setting (log_path_access) > env-var (CROWDEFIK_TRAEFIK_LOG_PATH).
    """
    from pathlib import Path as _Path
    from app.settings import get_settings
    from app.integrations.instance_settings import get_or_create_instance_settings
    from app.integrations.traefik_log_reader import LOOKBACK_HOURS

    s = get_settings()
    _inst = get_or_create_instance_settings(db)
    _db_log = getattr(_inst, "log_path_access", None)
    log_path: _Path | None = _Path(_db_log) if _db_log else s.traefik_log_path

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
            from app.integrations.traefik_log_reader import get_cached_index
            index = get_cached_index(log_path)
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


def enrich_abuse_scores(db: Session, batch_size: int = 15) -> int:
    """Pre-fetch AbuseIPDB scores for attacker IPs that are not yet cached or are stale.

    Runs during every sync cycle.  The batch is intentionally small (default 15) to
    stay well within AbuseIPDB's free-tier limit (1 000 req/day ≈ 41/hour ≈ 3/5 min).
    IPs are prioritised by alert frequency so the most-seen attackers get scores first.
    Only IPs whose score is absent or older than 7 days are queried.
    """
    from app.integrations import abuseipdb_client

    # Check if API key is configured at all — avoid 15 pointless DB reads otherwise
    from app.integrations.instance_settings import get_or_create_instance_settings
    inst = get_or_create_instance_settings(db)
    if not inst.abuseipdb_api_key_enc:
        return 0

    stale_cutoff = datetime.utcnow() - timedelta(days=7)

    # Most-attacked IPs that either have no abuse score or a stale one
    rows = (
        db.query(StoredAlert.source_ip)
        .filter(StoredAlert.source_ip.isnot(None))
        .distinct()
        .all()
    )
    candidate_ips = [r[0] for r in rows if r[0]]
    if not candidate_ips:
        return 0

    # Build a set of IPs that already have a fresh score
    cached_rows = (
        db.query(IpGeoCache.ip)
        .filter(
            IpGeoCache.ip.in_(candidate_ips),
            IpGeoCache.abuse_updated_at.isnot(None),
            IpGeoCache.abuse_updated_at >= stale_cutoff,
        )
        .all()
    )
    already_fresh = {r.ip for r in cached_rows}

    # IPs to enrich: prioritise by alert count (most attacked first)
    from sqlalchemy import func
    ip_counts = (
        db.query(StoredAlert.source_ip, func.count(StoredAlert.id).label("cnt"))
        .filter(StoredAlert.source_ip.in_(candidate_ips))
        .group_by(StoredAlert.source_ip)
        .order_by(func.count(StoredAlert.id).desc())
        .all()
    )
    to_enrich = [ip for ip, _ in ip_counts if ip not in already_fresh][:batch_size]

    if not to_enrich:
        return 0

    count = 0
    for ip in to_enrich:
        result = abuseipdb_client.check_ip(db, ip)
        if result is None:
            continue
        cache_row = db.get(IpGeoCache, ip)
        if cache_row is None:
            cache_row = IpGeoCache(ip=ip, updated_at=datetime.utcnow())
            db.add(cache_row)
        cache_row.abuse_score = result.get("abuseConfidenceScore")
        cache_row.abuse_total_reports = result.get("totalReports")
        cache_row.abuse_is_tor = result.get("isTor")
        cache_row.abuse_last_reported_at = result.get("lastReportedAt")
        cache_row.abuse_domain = result.get("domain")
        cache_row.abuse_updated_at = datetime.utcnow()
        # Also fill country_code from AbuseIPDB if geo hasn't set it yet
        if not cache_row.country_code and result.get("countryCode"):
            cache_row.country_code = result.get("countryCode")
        count += 1

    if count:
        db.commit()
        log.info("AbuseIPDB pre-fetch: scored %d IPs", count)

    return count


def _warm_traefik_cache(db: Session) -> None:
    """Refresh the Traefik router cache in the background so dashboard calls never block.

    The cache TTL is 2 hours; we refresh it every sync cycle (5 min) so it is
    always hot when the dashboard needs it.  Errors are silently swallowed —
    the dashboard will just show 0 routers until Traefik is reachable.
    """
    from app.core import cache as cache_mod
    from app.integrations import traefik_client

    try:
        routers = traefik_client.fetch_routers_sync(db)
        # Use set_value() instead of direct _store access to ensure thread-safety
        cache_mod.set_value("traefik:routers", routers, ttl_seconds=2 * 60 * 60)
        log.debug("Traefik router cache warmed: %d routers", len(routers))
    except Exception as exc:
        log.debug("Traefik cache warm skipped: %s", exc)


def _apply_service_policies(db: Session) -> int:
    """
    For each service that has auto_ban_enabled=True, find IPs that exceeded the
    configured thresholds and issue a ban if not already decided and not allowlisted.
    Returns the number of new bans issued.
    """
    import json as _json
    policies = db.query(ServicePolicy).filter(ServicePolicy.auto_ban_enabled == True).all()  # noqa: E712
    if not policies:
        return 0

    allowlisted = get_allowlisted_ips(db)
    bans_issued = 0

    for policy in policies:
        window_start = datetime.utcnow() - timedelta(hours=policy.auto_ban_window_hours)
        muted = set()
        if policy.muted_scenarios:
            try:
                muted = set(_json.loads(policy.muted_scenarios))
            except Exception:
                pass

        # Collect alert counts per IP within window for this service
        alerts_q = (
            db.query(StoredAlert.source_ip, StoredAlert.scenario)
            .filter(
                StoredAlert.target_host == policy.host,
                StoredAlert.start_at >= window_start,
                StoredAlert.source_ip != None,  # noqa: E711
            )
            .all()
        )

        ip_counts: dict[str, int] = {}
        for ip, scenario in alerts_q:
            if scenario in muted:
                continue
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        for ip, count in ip_counts.items():
            if ip in allowlisted:
                continue

            # Check event threshold
            if policy.auto_ban_min_events and count < policy.auto_ban_min_events:
                continue

            # Check abuse score threshold (from cache)
            if policy.auto_ban_min_score:
                from app.models import IpGeoCache
                geo = db.get(IpGeoCache, ip)
                if geo and geo.abuse_score is not None and geo.abuse_score < policy.auto_ban_min_score:
                    continue

            # Skip if already has an active decision
            existing = db.query(StoredDecision).filter(StoredDecision.ip_value == ip).first()
            if existing:
                continue

            # Issue the ban
            result = crowdsec_client.add_decision(
                db, ip=ip,
                duration=policy.auto_ban_duration,
                reason=f"auto-ban:{policy.host}",
                decision_type="ban",
            )
            if result.get("ok"):
                bans_issued += 1
                log.info("Auto-ban triggered: ip=%s host=%s events=%d duration=%s",
                         ip, policy.host, count, policy.auto_ban_duration)
            else:
                log.warning("Auto-ban failed for %s: %s", ip, result.get("error"))

    return bans_issued


def run_full_sync(db: Session) -> dict:
    """Fetch from CrowdSec, store in DB, enrich geo, cleanup old. Safe to call repeatedly."""
    alerts_raw = crowdsec_client.fetch_alerts_sync(db)
    decisions_raw = crowdsec_client.fetch_decisions_sync(db)

    new_alerts = sync_alerts(db, alerts_raw)
    new_decisions = sync_decisions(db, decisions_raw)
    geo_enriched = enrich_geo(db)
    abuse_scored = enrich_abuse_scores(db)
    backfill_target_hosts(db)
    cleaned = cleanup_old(db)
    auto_bans = _apply_service_policies(db)

    # Keep the Traefik router cache hot so dashboard endpoints never have to
    # wait for a live Traefik API call when serving user requests.
    _warm_traefik_cache(db)

    log.info(
        "Sync done: +%d alerts, +%d decisions, %d IPs geolocated, %d abuse scores fetched, "
        "%d old rows removed, %d auto-bans",
        new_alerts, new_decisions, geo_enriched, abuse_scored, cleaned, auto_bans,
    )
    return {
        "new_alerts": new_alerts,
        "new_decisions": new_decisions,
        "geo_enriched": geo_enriched,
        "abuse_scored": abuse_scored,
        "cleaned": cleaned,
        "auto_bans": auto_bans,
    }
