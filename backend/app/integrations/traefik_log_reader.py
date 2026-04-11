"""
Read Traefik access.log (JSON format) to correlate WAF alerts with target hosts.

CrowdSec AppSec / WAF direct alerts (kind=waf) don't include the HTTP Host header
in their alert context by default. This module parses the Traefik access.log to
find the virtual host that was targeted, by matching the attacker IP and timestamp.
"""
import json
import logging
import time
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import unquote

log = logging.getLogger(__name__)

# Number of lines to read from the end of the log file per sync run.
TAIL_LINES = 50_000
# Only keep log entries from the last N hours (WAF alerts are synced quickly).
LOOKBACK_HOURS = 24

# ── Index cache ───────────────────────────────────────────────────────────────
# The index is expensive to build (parse 50k lines). Cache it for INDEX_TTL
# seconds so that interactive "enrich" button clicks reuse the same index
# instead of re-reading the file on every request.

_INDEX_TTL = 60  # seconds
_index_cache: dict[str, tuple[float, dict]] = {}  # path → (built_at, index)
_index_lock = threading.Lock()


def get_cached_index(log_path: Path) -> dict[str, list[dict[str, Any]]]:
    """Return a cached IP→entries index, rebuilding it if older than INDEX_TTL."""
    key = str(log_path)
    now = time.monotonic()
    with _index_lock:
        if key in _index_cache:
            built_at, cached = _index_cache[key]
            if now - built_at < _INDEX_TTL:
                return cached
    # Build outside the lock so we don't block other threads during I/O
    fresh = build_ip_host_index(log_path)
    with _index_lock:
        _index_cache[key] = (now, fresh)
    return fresh


def invalidate_index_cache() -> None:
    """Force a rebuild on the next call (e.g. after a manual sync)."""
    with _index_lock:
        _index_cache.clear()


def _tail_file(path: Path, n: int) -> list[str]:
    """Return the last *n* non-empty text lines of *path* without loading the whole file."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            file_size = f.tell()
            if file_size == 0:
                return []

            chunk_size = 8192
            buf = b""
            pos = file_size

            while pos > 0:
                read = min(chunk_size, pos)
                pos -= read
                f.seek(pos)
                buf = f.read(read) + buf
                parts = buf.split(b"\n")
                non_empty = [p for p in parts if p.strip()]
                if len(non_empty) >= n:
                    return [p.decode("utf-8", errors="replace") for p in non_empty[-n:]]

            return [p.decode("utf-8", errors="replace") for p in buf.split(b"\n") if p.strip()]
    except OSError as exc:
        log.debug("Cannot read Traefik log %s: %s", path, exc)
        return []


def build_ip_host_index(log_path: Path) -> dict[str, list[dict[str, Any]]]:
    """
    Parse the last TAIL_LINES lines of a Traefik JSON access.log.

    Returns a dict mapping each client IP to a list of request records:
        { "1.2.3.4": [{"time": datetime, "host": "example.com", "path": "/foo"}, …] }

    Only entries from the last LOOKBACK_HOURS hours are kept.
    """
    if not log_path.exists():
        log.debug("Traefik log not found at %s", log_path)
        return {}

    cutoff = datetime.utcnow() - timedelta(hours=LOOKBACK_HOURS)
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    skipped = 0

    for raw in _tail_file(log_path, TAIL_LINES):
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            skipped += 1
            continue

        # ClientHost is the bare IP; ClientAddr is "ip:port"
        client_ip = (
            entry.get("ClientHost")
            or (entry.get("ClientAddr") or "").split(":")[0]
        )
        host = entry.get("RequestHost") or entry.get("RequestAddr") or ""
        path = entry.get("RequestPath") or entry.get("RequestURI") or ""
        time_str = entry.get("StartUTC") or entry.get("time") or ""

        if not (client_ip and host and time_str):
            continue

        try:
            ts = datetime.fromisoformat(time_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            continue

        if ts < cutoff:
            continue

        index[client_ip].append({"time": ts, "host": host, "path": path})

    total = sum(len(v) for v in index.values())
    log.debug("Traefik log index: %d IPs, %d entries (skipped %d)", len(index), total, skipped)
    return dict(index)


def find_host_for_alert(
    index: dict[str, list[dict[str, Any]]],
    source_ip: str,
    alert_time: datetime,
    target_uri: str | None = None,
    window_seconds: int = 60,
) -> str | None:
    """
    Look up the Traefik log index to find which host was targeted by this WAF alert.

    Match strategy:
    1. Same client IP as the attacker (source_ip).
    2. Request timestamp within *window_seconds* of the alert's start_at.
    3. If *target_uri* (request path) is given, prefer log entries whose path
       matches after URL-decoding (more precise when the IP hit multiple hosts).
    4. Fall back to the chronologically closest matching entry.

    Returns the target hostname or None if no match is found.
    """
    entries = index.get(source_ip)
    if not entries:
        return None

    candidates = [
        e for e in entries
        if abs((e["time"] - alert_time).total_seconds()) <= window_seconds
    ]
    if not candidates:
        return None

    # Prefer entries whose path matches the alert's target_uri
    if target_uri:
        decoded_uri = unquote(target_uri)
        uri_base = decoded_uri.split("?")[0]
        path_matches = [
            e for e in candidates
            if unquote(e["path"]).split("?")[0] == uri_base
        ]
        if path_matches:
            closest = min(path_matches, key=lambda e: abs((e["time"] - alert_time).total_seconds()))
            return closest["host"]

    # Fall back to the chronologically closest entry
    closest = min(candidates, key=lambda e: abs((e["time"] - alert_time).total_seconds()))
    return closest["host"]
