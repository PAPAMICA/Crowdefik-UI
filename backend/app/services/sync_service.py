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

    Tries multiple locations in order of reliability:
     1. events[*].meta  key=http_host / host  (Traefik access log parser)
     2. context list    key=http_host / host   (AppSec WAF)
     3. context list    key=target_uri → parse absolute URL host
     4. context list    key=http.request.host  (some custom parsers)
     5. alert.decisions[*].scope == "host" or "url"
     6. alert meta at top level (some aggregated alerts)

    Always strips the port (e.g. "example.com:443" → "example.com").
    Returns None if no host could be extracted.
    """
    from urllib.parse import urlparse as _urlparse

    def _clean(v: str) -> str | None:
        v = v.strip().lower()
        if not v or v in ("localhost", "127.0.0.1", "::1"):
            return None
        return v.split(":")[0]  # strip optional port

    # 1. Traefik-style: events[*].meta[key=http_host / host]
    events = alert.get("events") or []
    for event in events:
        meta = event.get("meta") or []
        for m in meta:
            if isinstance(m, dict):
                key = (m.get("key") or "").lower()
                if key in ("http_host", "http.host", "host", "http.request.host", "server_name"):
                    value = str(m.get("value") or "").strip()
                    if value:
                        cleaned = _clean(value)
                        if cleaned:
                            return cleaned

    # 2, 3, 4. AppSec WAF context list
    context = alert.get("context") or []
    target_uri: str | None = None
    for c in context:
        if isinstance(c, dict):
            key = (c.get("key") or "").lower()
            value = str(c.get("value") or "").strip()
            if not value:
                continue
            if key in ("http_host", "http.host", "host", "http.request.host", "server_name"):
                cleaned = _clean(value)
                if cleaned:
                    return cleaned
            if key in ("target_uri", "http.request.uri", "request_uri"):
                target_uri = target_uri or value  # keep first

    if target_uri:
        try:
            parsed = _urlparse(target_uri)
            if parsed.hostname:
                cleaned = _clean(parsed.hostname)
                if cleaned:
                    return cleaned
        except Exception:
            pass

    # 5. decisions[*].scope for host-scoped decisions
    for d in (alert.get("decisions") or []):
        scope = str(d.get("scope") or "").lower()
        value = str(d.get("value") or "").strip()
        if scope in ("host", "url") and value:
            try:
                h = _urlparse(value).hostname or value
                cleaned = _clean(h)
                if cleaned and "." in cleaned:
                    return cleaned
            except Exception:
                cleaned = _clean(value)
                if cleaned and "." in cleaned:
                    return cleaned

    # 6. Top-level meta array (aggregated alert format)
    for m in (alert.get("meta") or []):
        if isinstance(m, dict):
            key = (m.get("key") or "").lower()
            if key in ("http_host", "host", "http.request.host"):
                value = str(m.get("value") or "").strip()
                if value:
                    cleaned = _clean(value)
                    if cleaned:
                        return cleaned

    return None


def sync_alerts(db: Session, alerts: list[dict]) -> int:
    """Upsert alerts. Returns count of new rows inserted.

    For existing alerts that still have no target_host, we attempt a fresh
    extraction from the (possibly updated) raw JSON — e.g. when CrowdSec
    retroactively enriches an alert with context fields.
    """
    if not alerts:
        return 0
    now = datetime.utcnow()

    # Pre-load existing rows in one query (id → row) to eliminate N+1 SELECTs
    incoming_ids = [a["id"] for a in alerts if isinstance(a.get("id"), int)]
    existing_rows: dict[int, StoredAlert] = {
        r.id: r
        for r in db.query(StoredAlert).filter(StoredAlert.id.in_(incoming_ids)).all()
    }

    inserted = 0
    host_updated = 0
    for a in alerts:
        alert_id = a.get("id")
        if not isinstance(alert_id, int):
            continue

        if alert_id in existing_rows:
            # Alert already stored — only try to update target_host if still missing
            existing = existing_rows[alert_id]
            if not existing.target_host:
                host = _extract_target_host(a)
                if host:
                    existing.target_host = host
                    # Reset enrichment flag so backfill skips the log-read for this row
                    existing.log_enrichment_attempted = True
                    host_updated += 1
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

    if inserted or host_updated:
        db.commit()
    if host_updated:
        log.debug("sync_alerts: updated target_host for %d existing alerts", host_updated)
    return inserted


def _top_host_for_ips(db: Session, ips: list[str]) -> dict[str, str]:
    """Return {ip: most_common_target_host} for a list of IPs (single query)."""
    from sqlalchemy import func
    from collections import defaultdict as _dd

    if not ips:
        return {}
    rows = (
        db.query(StoredAlert.source_ip, StoredAlert.target_host, func.count(StoredAlert.id).label("n"))
        .filter(StoredAlert.source_ip.in_(ips), StoredAlert.target_host.isnot(None))
        .group_by(StoredAlert.source_ip, StoredAlert.target_host)
        .all()
    )
    ip_host_counts: dict[str, list[tuple[str, int]]] = _dd(list)
    for ip, host, n in rows:
        ip_host_counts[ip].append((host, n))

    result: dict[str, str] = {}
    for ip, host_counts in ip_host_counts.items():
        top_host = max(host_counts, key=lambda x: x[1])[0]
        result[ip] = top_host
    return result


def sync_decisions(db: Session, decisions: list[dict]) -> int:
    if not decisions:
        return 0
    now = datetime.utcnow()

    # Pre-load all existing IDs in one query to eliminate N+1 SELECT per decision
    incoming_ids = [d["id"] for d in decisions if isinstance(d.get("id"), int)]
    existing_ids: set[int] = {
        r[0] for r in db.query(StoredDecision.id).filter(StoredDecision.id.in_(incoming_ids)).all()
    }

    # Collect IPs for the new decisions so we can look up their target host in one batch
    new_decisions = [d for d in decisions if isinstance(d.get("id"), int) and d["id"] not in existing_ids]
    new_ips = list({str(d.get("value") or d.get("ip") or "") for d in new_decisions if d.get("value") or d.get("ip")})
    ip_to_host = _top_host_for_ips(db, new_ips) if new_ips else {}

    inserted = 0
    for d in new_decisions:
        ip = str(d.get("value") or d.get("ip") or "")
        row = StoredDecision(
            id=d["id"],
            ip_value=ip,
            decision_type=str(d.get("type") or ""),
            scope=str(d.get("scope") or ""),
            scenario=str(d.get("scenario") or ""),
            duration_str=str(d.get("duration") or ""),
            until=_parse_dt(d.get("until")),
            target_host=ip_to_host.get(ip),
            raw_json=json.dumps(d),
            synced_at=now,
        )
        db.add(row)
        inserted += 1
    if inserted:
        db.commit()
    return inserted


def backfill_decisions_target_host(db: Session) -> int:
    """Populate target_host on StoredDecision rows that still have NULL.

    Called during run_full_sync so decisions imported before this column existed
    get enriched automatically without requiring manual intervention.
    """
    rows = db.query(StoredDecision).filter(StoredDecision.target_host.is_(None)).all()
    if not rows:
        return 0

    ips = list({r.ip_value for r in rows if r.ip_value})
    ip_to_host = _top_host_for_ips(db, ips) if ips else {}
    if not ip_to_host:
        return 0

    updated = 0
    for row in rows:
        host = ip_to_host.get(row.ip_value)
        if host:
            row.target_host = host
            updated += 1

    if updated:
        db.commit()
        log.info("Backfilled target_host for %d decisions", updated)
    return updated


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

    Pass 1 — Fast: re-parse raw_json (works when CrowdSec includes http_host in meta).
    Pass 2 — Log correlation: match by IP + timestamp against Traefik access.log.
    Pass 3 — IP heuristic: if the same IP attacked a known host in other alerts, use it.

    The flag `log_enrichment_attempted` is set to True ONLY when the log was
    actually read.  If the log file is unavailable the flag is NOT set so the
    alert will be retried on the next sync cycle.
    """
    rows = db.query(StoredAlert).filter(StoredAlert.target_host.is_(None)).all()
    if not rows:
        return 0

    updated = 0
    need_log_correlation: list[StoredAlert] = []

    # Pass 1: re-parse raw_json
    for row in rows:
        try:
            data = json.loads(row.raw_json)
            host = _extract_target_host(data)
            if host:
                row.target_host = host
                updated += 1
                continue
        except Exception:
            pass
        if not row.log_enrichment_attempted:
            need_log_correlation.append(row)

    if updated:
        db.commit()

    # Pass 2: Traefik log correlation
    if need_log_correlation:
        updated += _backfill_from_traefik_log(db, need_log_correlation)

    # Pass 3: IP heuristic — fill remaining unenriched alerts
    still_none = db.query(StoredAlert).filter(StoredAlert.target_host.is_(None)).all()
    if still_none:
        updated += _enrich_by_ip_heuristic(db, still_none)

    return updated


def _build_log_index(db: Session) -> dict:
    """
    Build the Traefik log index with full fallback chain:
      1. Configured file path (DB setting > env var)
      2. Docker exec via configured container name

    Returns the index dict (empty dict means log unavailable).
    """
    from pathlib import Path as _Path
    from app.settings import get_settings
    from app.integrations.instance_settings import get_or_create_instance_settings
    from app.integrations.traefik_log_reader import get_cached_index, get_cached_docker_index

    s = get_settings()
    _inst = get_or_create_instance_settings(db)
    _db_log = getattr(_inst, "log_path_access", None)
    log_path: _Path | None = _Path(_db_log) if _db_log else s.traefik_log_path
    container_name: str = getattr(_inst, "traefik_container_name", None) or "traefik"

    # Use cached index if the file path is known and exists
    if log_path and log_path.exists():
        try:
            return get_cached_index(log_path)
        except Exception as exc:
            log.warning("Traefik log index build failed (file): %s", exc)

    # Fallback: Docker exec — also cached to avoid OOM on repeated enrich calls
    try:
        docker_paths = [
            "/var/log/traefik/access.log",
            "/var/log/access.log",
        ]
        index = get_cached_docker_index(container_name, docker_paths)
        if index:
            return index
    except Exception as exc:
        log.debug("Traefik log index via Docker fallback failed: %s", exc)

    return {}


def _backfill_from_traefik_log(db: Session, rows: list[StoredAlert]) -> int:
    """
    Correlate WAF alerts (no target_host, not yet tried) against the Traefik
    access.log.

    Key behaviour changes vs. previous version:
    - The `log_enrichment_attempted` flag is ONLY set when the log index was
      successfully built (non-empty). If the log is unavailable, the flag is
      left as False so the next sync cycle retries automatically.
    - Old alerts (beyond LOOKBACK_HOURS) are marked as attempted unconditionally
      because the log will never contain them.
    """
    from app.integrations.traefik_log_reader import LOOKBACK_HOURS, find_host_for_alert

    # Restrict to alerts recent enough to potentially still be in the log.
    cutoff = datetime.utcnow() - timedelta(hours=LOOKBACK_HOURS)
    candidates = [r for r in rows if r.start_at and r.start_at >= cutoff]

    # Alerts older than the lookback window can never be found in the log.
    # Mark them attempted once so they move to the IP-heuristic pass only.
    too_old = [r for r in rows if r not in candidates]
    if too_old:
        for r in too_old:
            r.log_enrichment_attempted = True
        db.commit()

    if not candidates:
        return 0

    # Build index (with Docker exec fallback)
    index = _build_log_index(db)

    if not index:
        # Log unavailable — do NOT mark as attempted; retry on next sync.
        log.debug("Traefik log unavailable — will retry enrichment on next sync (%d alerts pending)", len(candidates))
        return 0

    updated = 0
    for row in candidates:
        # Now that we have a valid index, mark as attempted regardless of result.
        row.log_enrichment_attempted = True

        if not row.source_ip or not row.start_at:
            continue

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
        log.info("Traefik log correlation: enriched %d / %d alerts", updated, len(candidates))
    else:
        log.debug("Traefik log correlation: 0 / %d alerts matched (index had %d IPs)", len(candidates), len(index))

    return updated


def _enrich_by_ip_heuristic(db: Session, rows: list[StoredAlert]) -> int:
    """
    Fallback enrichment: if all other historical alerts from the same attacker IP
    point to the same target_host, assign that host to the unenriched alert.

    This handles cases where:
    - The log was unavailable when the alert arrived.
    - The alert is too old to be in the log.
    - The IP was seen hitting only one service in the last 7 days.
    """
    from sqlalchemy import func

    if not rows:
        return 0

    ips = list({r.source_ip for r in rows if r.source_ip})
    if not ips:
        return 0

    # For each IP, find the most common target_host from OTHER enriched alerts.
    ip_to_host: dict[str, str] = {}
    results = (
        db.query(StoredAlert.source_ip, StoredAlert.target_host, func.count(StoredAlert.id).label("n"))
        .filter(
            StoredAlert.source_ip.in_(ips),
            StoredAlert.target_host.isnot(None),
        )
        .group_by(StoredAlert.source_ip, StoredAlert.target_host)
        .all()
    )
    # Group by IP and pick the dominant host (must be ≥60% of alerts for that IP)
    from collections import defaultdict as _dd
    ip_host_counts: dict[str, list[tuple[str, int]]] = _dd(list)
    for ip, host, cnt in results:
        ip_host_counts[ip].append((host, cnt))

    for ip, host_counts in ip_host_counts.items():
        total = sum(c for _, c in host_counts)
        top_host, top_count = max(host_counts, key=lambda x: x[1])
        if total >= 2 and top_count / total >= 0.6:
            ip_to_host[ip] = top_host

    if not ip_to_host:
        return 0

    updated = 0
    for row in rows:
        if row.source_ip and row.source_ip in ip_to_host and not row.target_host:
            row.target_host = ip_to_host[row.source_ip]
            updated += 1

    if updated:
        db.commit()
        log.info("IP heuristic enrichment: %d alerts assigned target_host", updated)

    return updated


def _re_enrich_recent_unenriched(db: Session) -> int:
    """
    Periodically reset `log_enrichment_attempted` for recent alerts that still
    have no target_host, allowing the next sync cycle to retry them.

    This handles the case where:
    - The Traefik log path was configured AFTER the alerts were synced.
    - The Docker socket wasn't available at first sync.
    - The log index was stale / cold.

    Only resets alerts from the last 72 hours to avoid infinite retry loops.
    """
    cutoff = datetime.utcnow() - timedelta(hours=72)
    rows = (
        db.query(StoredAlert)
        .filter(
            StoredAlert.target_host.is_(None),
            StoredAlert.log_enrichment_attempted == True,  # noqa: E712
            StoredAlert.start_at >= cutoff,
        )
        .all()
    )
    if not rows:
        return 0
    for r in rows:
        r.log_enrichment_attempted = False
    db.commit()
    log.debug("Reset enrichment flag for %d recent unenriched alerts (will retry)", len(rows))
    return len(rows)


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

    # Reset the attempted flag for recent alerts that still have no host,
    # so the upcoming backfill gets a fresh chance (handles late log config).
    _re_enrich_recent_unenriched(db)
    host_enriched = backfill_target_hosts(db)

    # Backfill target_host on decisions (fast: single GROUP BY query per batch)
    backfill_decisions_target_host(db)

    cleaned = cleanup_old(db)
    auto_bans = _apply_service_policies(db)

    # Keep the Traefik router cache hot so dashboard endpoints never have to
    # wait for a live Traefik API call when serving user requests.
    _warm_traefik_cache(db)

    log.info(
        "Sync done: +%d alerts, +%d decisions, %d IPs geolocated, %d abuse scores fetched, "
        "%d hosts enriched, %d old rows removed, %d auto-bans",
        new_alerts, new_decisions, geo_enriched, abuse_scored, host_enriched, cleaned, auto_bans,
    )
    return {
        "new_alerts": new_alerts,
        "new_decisions": new_decisions,
        "geo_enriched": geo_enriched,
        "abuse_scored": abuse_scored,
        "host_enriched": host_enriched,
        "cleaned": cleaned,
        "auto_bans": auto_bans,
    }
