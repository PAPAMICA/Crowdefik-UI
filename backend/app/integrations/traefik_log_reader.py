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

# ── Tuning constants ──────────────────────────────────────────────────────────
# Tail enough lines to cover 3 days of typical traffic on a busy server.
TAIL_LINES = 200_000
# Correlation window: WAF alerts may arrive minutes after the request; allow 5 min.
MATCH_WINDOW_SECONDS = 300
# Keep log entries up to 72 hours for backfill of older alerts.
LOOKBACK_HOURS = 72

# ── Index cache ───────────────────────────────────────────────────────────────
# The index is expensive to build (parse 200 k lines). Cache it for INDEX_TTL
# seconds so that interactive "enrich" button clicks reuse the same index
# instead of re-reading the file on every request.

_INDEX_TTL = 120  # seconds — refreshed automatically on each sync cycle
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

            chunk_size = 65536  # larger chunks for faster tail on big files
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


def _tail_docker(container: str, log_path_in_container: str, n: int) -> list[str]:
    """Read the last *n* lines of a log file inside a Docker container via exec."""
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "exec", container, "tail", "-n", str(n), log_path_in_container],
            capture_output=True, text=True, timeout=15,
        )
        return [l for l in result.stdout.splitlines() if l.strip()]
    except Exception as exc:
        log.debug("Docker exec tail %s:%s failed: %s", container, log_path_in_container, exc)
        return []


def build_ip_host_index(
    log_path: Path | None,
    docker_container: str | None = None,
    docker_log_paths: list[str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """
    Parse the last TAIL_LINES lines of a Traefik JSON access.log.

    Returns a dict mapping each client IP to a list of request records:
        { "1.2.3.4": [{"time": datetime, "host": "example.com", "path": "/foo"}, …] }

    Only entries from the last LOOKBACK_HOURS hours are kept.
    Falls back to Docker exec if the file path is unavailable.

    The index also maps X-Forwarded-For IPs so it can match alerts from
    upstream clients that sent requests through a proxy.
    """
    raw_lines: list[str] = []
    source_desc = "unavailable"

    if log_path and log_path.exists():
        raw_lines = _tail_file(log_path, TAIL_LINES)
        source_desc = str(log_path)
    elif docker_container:
        candidate_paths = docker_log_paths or [
            "/var/log/traefik/access.log",
            "/var/log/access.log",
        ]
        for cp in candidate_paths:
            lines = _tail_docker(docker_container, cp, TAIL_LINES)
            if lines:
                raw_lines = lines
                source_desc = f"docker:{docker_container}:{cp}"
                break

    if not raw_lines:
        log.debug("Traefik log unavailable (source=%s)", source_desc)
        return {}

    cutoff = datetime.utcnow() - timedelta(hours=LOOKBACK_HOURS)
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    skipped = 0

    for raw in raw_lines:
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
        host = (entry.get("RequestHost") or entry.get("RequestAddr") or "").lower().split(":")[0]
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

        record = {"time": ts, "host": host, "path": path}
        index[client_ip].append(record)

        # Also index X-Forwarded-For / X-Real-Ip headers so alerts from proxied
        # clients can be matched even when CrowdSec sees the original client IP.
        for xff_header in ("X-Forwarded-For", "x-forwarded-for", "X-Real-Ip"):
            xff = entry.get(xff_header) or ""
            if xff:
                # X-Forwarded-For can be comma-separated ("ip1, ip2, ip3")
                for xff_ip in [x.strip() for x in xff.split(",") if x.strip()]:
                    if xff_ip != client_ip:
                        index[xff_ip].append(record)

    total = sum(len(v) for v in index.values())
    log.debug(
        "Traefik log index built from %s: %d IPs, %d entries (skipped %d non-JSON)",
        source_desc, len(index), total, skipped,
    )
    return dict(index)


def find_host_for_alert(
    index: dict[str, list[dict[str, Any]]],
    source_ip: str,
    alert_time: datetime,
    target_uri: str | None = None,
    window_seconds: int = MATCH_WINDOW_SECONDS,
) -> str | None:
    """
    Look up the Traefik log index to find which host was targeted by this WAF alert.

    Match strategy (in order of precision):
    1. Same client IP as the attacker (source_ip) — or via X-Forwarded-For (indexed).
    2. Request timestamp within *window_seconds* of the alert's start_at.
    3. If *target_uri* (request path) is given, prefer log entries whose path
       matches after URL-decoding (more precise when the IP hit multiple hosts).
    4. Fall back to the chronologically closest matching entry.
    5. If multiple hosts match, pick the most frequent one in the candidate window.

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

    # Strategy 1: exact path match (highest confidence)
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

    # Strategy 2: if only one host in the window, return it (no ambiguity)
    hosts_in_window = {e["host"] for e in candidates}
    if len(hosts_in_window) == 1:
        return candidates[0]["host"]

    # Strategy 3: most frequently seen host in the window
    from collections import Counter
    host_counts = Counter(e["host"] for e in candidates)
    top_host, top_count = host_counts.most_common(1)[0]
    # Only use most-frequent if it's clearly dominant (>50% of candidates)
    if top_count >= len(candidates) * 0.5:
        return top_host

    # Strategy 4: chronologically closest entry
    closest = min(candidates, key=lambda e: abs((e["time"] - alert_time).total_seconds()))
    return closest["host"]
