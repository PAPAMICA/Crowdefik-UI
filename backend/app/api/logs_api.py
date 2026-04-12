"""
Unified log viewer API.

Three log sources:
  GET /api/logs/access    — Traefik JSON access log (structured table)
  GET /api/logs/traefik   — Traefik application log (text/structured lines)
  GET /api/logs/crowdsec  — CrowdSec log (via docker exec or mounted file)

All endpoints share these query params:
  lines  (int, default 1000): how many raw lines to consider before filtering.
  minutes (int, default 0):   additional time-window filter (0 = disabled).

When a search / host / level filter is provided the backend runs a native
grep pipeline (grep … | tail -n N) instead of reading all N lines into
Python first.  This keeps large-file reads fast.
"""
import json as _json
import logging
import re
import shlex
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import get_db
from app.models import IpGeoCache, User
from app.settings import get_settings

router = APIRouter(prefix="/logs", tags=["logs"])
log = logging.getLogger(__name__)

_DEFAULT_LIMIT   = 200
_DEFAULT_LINES   = 1_000
_MAX_LINES       = 50_000
_DEFAULT_MINUTES = 0   # disabled by default — lines-based is the primary control


# ── log-path resolution ───────────────────────────────────────────────────────

def _resolve_path(db: Session, db_attr: str, env_path: Path | None) -> Path | None:
    """Return effective log path: DB setting > env var.

    Checks the DB value first (set from the Settings UI), falls back to the
    env-var-based path from app settings.  Returns *None* when neither is set.
    """
    from app.integrations.instance_settings import get_or_create_instance_settings
    try:
        row = get_or_create_instance_settings(db)
        db_val = getattr(row, db_attr, None)
        if db_val:
            return Path(db_val)
    except Exception:
        pass
    return env_path


def _get_container_name(db: Session, field: str, default: str) -> str:
    from app.integrations.instance_settings import get_or_create_instance_settings
    row = get_or_create_instance_settings(db)
    return getattr(row, field, None) or default


def _attach_geo(db: Session, entries: list[dict[str, Any]]) -> None:
    """Attach country_code + abuse_score to each entry from IpGeoCache (single batch query).

    Only reads from cache — never triggers external API calls.
    Missing IPs simply get null values.
    """
    ips = {e["client_ip"] for e in entries if e.get("client_ip")}
    if not ips:
        return
    rows = (
        db.query(IpGeoCache.ip, IpGeoCache.country_code, IpGeoCache.abuse_score)
        .filter(IpGeoCache.ip.in_(ips))
        .all()
    )
    lookup: dict[str, tuple[str | None, int | None]] = {
        r.ip: (r.country_code, r.abuse_score) for r in rows
    }
    for e in entries:
        ip = e.get("client_ip")
        cc, score = lookup.get(ip, (None, None)) if ip else (None, None)
        e["country_code"] = cc
        e["abuse_score"] = score


# ── time helpers ──────────────────────────────────────────────────────────────

def _parse_log_time(t: str) -> datetime | None:
    """Parse a log timestamp string (ISO-8601 or Traefik logfmt) to UTC datetime."""
    if not t:
        return None
    t = t.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(t[:len(fmt)], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _cutoff(minutes: int) -> datetime | None:
    if minutes <= 0:
        return None
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


# ── grep / I/O helpers ────────────────────────────────────────────────────────

def _tail(path: Path, n: int) -> list[str]:
    """Read last *n* lines from *path* efficiently (pure Python, no subprocess)."""
    n = max(1, min(n, _MAX_LINES))
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            buf = b""
            chunk = 65536
            found = 0
            pos = size
            while pos > 0 and found <= n:
                read = min(chunk, pos)
                pos -= read
                fh.seek(pos)
                buf = fh.read(read) + buf
                found = buf.count(b"\n")
            lines = buf.decode("utf-8", errors="replace").splitlines()
            return lines[-n:] if len(lines) > n else lines
    except Exception as exc:
        log.warning("_tail(%s): %s", path, exc)
        return []


def _grep_file(path: Path, grep_terms: list[str], n: int) -> list[str]:
    """tail -n MAX | grep term1 | grep term2 | tail -n N  — run as sh -c pipeline."""
    n = max(1, min(n, _MAX_LINES))
    quoted_path = shlex.quote(str(path))
    parts: list[str] = [f"tail -n {_MAX_LINES} {quoted_path}"]
    for term in grep_terms:
        parts.append(f"grep -ia {shlex.quote(term)}")
    parts.append(f"tail -n {n}")
    pipeline = " | ".join(parts)
    try:
        result = subprocess.run(
            ["sh", "-c", pipeline],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout.splitlines()
    except Exception as exc:
        log.warning("grep pipeline failed (%s): %s — falling back to _tail", path, exc)
        return _tail(path, n)


def _docker_exec(container: str, cmd: list[str]) -> list[str]:
    """Run a command inside *container* and return stdout lines."""
    try:
        result = subprocess.run(
            ["docker", "exec", container] + cmd,
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout.splitlines()
    except Exception as exc:
        log.warning("docker exec %s %s: %s", container, cmd, exc)
        return []


def _docker_grep(container: str, log_path: str, grep_terms: list[str], n: int) -> list[str]:
    """Same grep pipeline but inside a docker container via sh -c."""
    n = max(1, min(n, 5000))
    quoted_path = shlex.quote(log_path)
    parts: list[str] = [f"tail -n {_MAX_LINES} {quoted_path} 2>/dev/null"]
    for term in grep_terms:
        parts.append(f"grep -ia {shlex.quote(term)}")
    parts.append(f"tail -n {n}")
    pipeline = " | ".join(parts)
    return _docker_exec(container, ["sh", "-c", pipeline])


def _read_log_lines(
    path: Path | None,
    container: str | None,
    container_paths: list[str],
    n: int,
    grep_terms: list[str],
) -> tuple[list[str], str]:
    """Return (lines, source) from file or docker, with optional grep pre-filter."""
    n = max(1, min(n, _MAX_LINES))

    if path and path.exists():
        if grep_terms:
            return _grep_file(path, grep_terms, n), "file"
        return _tail(path, n), "file"

    if container:
        for cpath in container_paths:
            if grep_terms:
                lines = _docker_grep(container, cpath, grep_terms, n)
            else:
                lines = _docker_exec(container, ["tail", "-n", str(min(n, 5000)), cpath])
            if lines:
                return lines, "docker"

    return [], "unavailable"


# ── access log ────────────────────────────────────────────────────────────────

@router.get("/access")
def access_logs(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    lines: int = _DEFAULT_LINES,
    limit: int = _DEFAULT_LIMIT,
    page: int = 1,
    minutes: int = _DEFAULT_MINUTES,
    host: str | None = None,
    search: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Traefik JSON access log — filterable, paginated."""
    s = get_settings()
    log_path = _resolve_path(db, "log_path_access", s.traefik_log_path)
    if not log_path or not log_path.exists():
        return {"available": False, "total": 0, "entries": [], "lines": lines}

    # Build grep pre-filter terms: search text and host string are both safe to
    # pass to grep as plain text pre-filters (Python does precise re-checking).
    grep_terms: list[str] = []
    if search:
        grep_terms.append(search)
    if host:
        # pre-filter: host appears somewhere in the JSON line
        grep_terms.append(host)

    raw_lines, _source = _read_log_lines(log_path, None, [], lines, grep_terms)

    entries: list[dict[str, Any]] = []
    search_lc = search.lower() if search else None
    host_lc = host.lower() if host else None
    cut = _cutoff(minutes)

    for line in reversed(raw_lines):
        try:
            e = _json.loads(line)
        except _json.JSONDecodeError:
            continue

        entry_host = (e.get("RequestHost") or "").lower().split(":")[0]
        code = e.get("DownstreamStatus") or e.get("OriginStatus")
        method = e.get("RequestMethod", "")
        path_val = e.get("RequestPath") or e.get("RequestURI", "")
        client = (e.get("ClientHost") or (e.get("ClientAddr") or "").split(":")[0])
        time_str = e.get("StartUTC") or e.get("time") or ""

        if cut:
            dt = _parse_log_time(time_str)
            if dt and dt < cut:
                break  # reversed order: older entries follow — stop early

        if host_lc and entry_host != host_lc:
            continue
        if status:
            cat = str(code)[0] + "xx" if code else ""
            if status != cat and str(code) != status:
                continue
        if search_lc:
            haystack = f"{entry_host} {path_val} {client} {method} {code}".lower()
            if search_lc not in haystack:
                continue

        entries.append({
            "time": time_str,
            "host": entry_host,
            "method": method,
            "path": path_val,
            "status": code,
            "client_ip": client,
            "duration_ms": round((e.get("Duration") or 0) / 1_000_000, 1),
            "bytes": e.get("DownstreamContentSize"),
            "router": e.get("RouterName"),
            "service": e.get("ServiceName"),
            "tls_version": e.get("TLSVersion"),
        })

    limit = max(1, min(limit, 1000))
    total = len(entries)
    paged = entries[(page - 1) * limit: page * limit]
    _attach_geo(db, paged)
    return {
        "available": True,
        "total": total,
        "page": page,
        "pages": -(-total // limit),
        "lines": lines,
        "entries": paged,
    }


# ── access log stats ──────────────────────────────────────────────────────────

@router.get("/access/stats")
def access_log_stats(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    lines: int = _DEFAULT_LINES,
    minutes: int = _DEFAULT_MINUTES,
    host: str | None = None,
    search: str | None = None,
    status: str | None = None,
    top_n: int = 10,
) -> dict[str, Any]:
    """Aggregated statistics from the Traefik access log for chart rendering.

    Returns top hosts, methods, status distribution and top client IPs across
    the same filtered dataset as GET /access (without pagination).
    """
    from collections import Counter

    s = get_settings()
    log_path = _resolve_path(db, "log_path_access", s.traefik_log_path)
    if not log_path or not log_path.exists():
        return {"available": False, "top_hosts": [], "top_methods": [], "status_dist": [], "top_ips": []}

    grep_terms: list[str] = []
    if search:
        grep_terms.append(search)
    if host:
        grep_terms.append(host)

    raw_lines, _source = _read_log_lines(log_path, None, [], lines, grep_terms)

    search_lc = search.lower() if search else None
    host_lc = host.lower() if host else None
    cut = _cutoff(minutes)
    top_n = max(5, min(top_n, 50))

    hosts_ctr: Counter[str] = Counter()
    methods_ctr: Counter[str] = Counter()
    status_ctr: Counter[str] = Counter()
    ips_ctr: Counter[str] = Counter()

    for line in raw_lines:
        try:
            e = _json.loads(line)
        except _json.JSONDecodeError:
            continue

        entry_host = (e.get("RequestHost") or "").lower().split(":")[0]
        code = e.get("DownstreamStatus") or e.get("OriginStatus")
        method = e.get("RequestMethod", "")
        path_val = e.get("RequestPath") or e.get("RequestURI", "")
        client = (e.get("ClientHost") or (e.get("ClientAddr") or "").split(":")[0])
        time_str = e.get("StartUTC") or e.get("time") or ""

        if cut:
            dt = _parse_log_time(time_str)
            if dt and dt < cut:
                continue

        if host_lc and entry_host != host_lc:
            continue
        if status:
            cat = str(code)[0] + "xx" if code else ""
            if status != cat and str(code) != status:
                continue
        if search_lc:
            haystack = f"{entry_host} {path_val} {client} {method} {code}".lower()
            if search_lc not in haystack:
                continue

        if entry_host:
            hosts_ctr[entry_host] += 1
        if method:
            methods_ctr[method.upper()] += 1
        if client:
            ips_ctr[client] += 1
        if code:
            cat = f"{str(code)[0]}xx" if str(code) and str(code)[0].isdigit() else "other"
            status_ctr[cat] += 1

    # Attach country codes to top IPs from geo cache (batch)
    top_ip_list = [ip for ip, _ in ips_ctr.most_common(top_n)]
    geo_rows = (
        db.query(IpGeoCache.ip, IpGeoCache.country_code, IpGeoCache.abuse_score)
        .filter(IpGeoCache.ip.in_(top_ip_list))
        .all()
    ) if top_ip_list else []
    geo_map = {r.ip: (r.country_code, r.abuse_score) for r in geo_rows}

    return {
        "available": True,
        "total_entries": sum(hosts_ctr.values()),
        "top_hosts": [{"host": h, "count": c} for h, c in hosts_ctr.most_common(top_n)],
        "top_methods": [{"method": m, "count": c} for m, c in methods_ctr.most_common()],
        "status_dist": [
            {"status": s, "count": c}
            for s, c in sorted(status_ctr.items())
        ],
        "top_ips": [
            {
                "ip": ip,
                "count": ips_ctr[ip],
                "country_code": geo_map.get(ip, (None, None))[0],
                "abuse_score": geo_map.get(ip, (None, None))[1],
            }
            for ip in top_ip_list
        ],
    }


# ── generic structured-log parser & filter ────────────────────────────────────

_LOG_RE = re.compile(
    r'time="(?P<time>[^"]+)".*level=(?P<level>\w+)\s+msg="(?P<msg>[^"]*)"'
)


def _parse_log_line(line: str) -> dict[str, str] | None:
    if line.startswith("{"):
        try:
            d = _json.loads(line)
            return {
                "time":  d.get("time", ""),
                "level": (d.get("level") or "info").lower(),
                "msg":   d.get("msg", d.get("message", "")),
                "raw":   line,
            }
        except Exception:
            pass
    m = _LOG_RE.search(line)
    if m:
        return {
            "time":  m.group("time"),
            "level": m.group("level").lower(),
            "msg":   m.group("msg"),
            "raw":   line,
        }
    if line.strip():
        return {"time": "", "level": "info", "msg": line.strip(), "raw": line}
    return None


def _filter_log_entries(
    raw_lines: list[str],
    *,
    cut: datetime | None,
    level_lc: str | None,
    search_lc: str | None,
) -> list[dict[str, str]]:
    """Parse + precisely filter lines already pre-filtered by grep."""
    entries: list[dict[str, str]] = []
    for line in reversed(raw_lines):
        parsed = _parse_log_line(line)
        if not parsed:
            continue
        if cut:
            dt = _parse_log_time(parsed["time"])
            if dt and dt < cut:
                break
        if level_lc and parsed["level"] != level_lc:
            continue
        if search_lc and search_lc not in parsed["msg"].lower() and search_lc not in parsed["raw"].lower():
            continue
        entries.append(parsed)
    return entries


def _level_grep_term(level: str) -> str:
    """Return a grep pattern that matches both logfmt (level=X) and JSON ("level":"X")."""
    # Use a pattern broad enough to avoid missing either format.
    # Example: 'level.{0,3}error' matches 'level=error' and '"level":"error"'
    return f"level.{{0,3}}{re.escape(level.lower())}"


# ── traefik app log ───────────────────────────────────────────────────────────

@router.get("/traefik")
def traefik_logs(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    lines: int = _DEFAULT_LINES,
    limit: int = _DEFAULT_LIMIT,
    page: int = 1,
    minutes: int = _DEFAULT_MINUTES,
    level: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """Traefik application log — file or docker exec fallback."""
    s = get_settings()
    log_path = _resolve_path(db, "log_path_traefik", s.traefik_app_log_path)
    container = _get_container_name(db, "traefik_container_name", "traefik")
    container_paths = [
        "/var/log/traefik/traefik.log",
        "/var/log/traefik.log",
    ]

    # Build grep terms for pre-filtering (precise filtering still done in Python)
    grep_terms: list[str] = []
    if search:
        grep_terms.append(search)
    if level:
        grep_terms.append(_level_grep_term(level))

    raw_lines, source = _read_log_lines(log_path, container, container_paths, lines, grep_terms)

    if not raw_lines:
        return {"available": False, "total": 0, "entries": [], "lines": lines, "source": source}

    entries = _filter_log_entries(
        raw_lines,
        cut=_cutoff(minutes),
        level_lc=level.lower() if level else None,
        search_lc=search.lower() if search else None,
    )

    limit = max(1, min(limit, 2000))
    total = len(entries)
    paged = entries[(page - 1) * limit: page * limit]
    return {
        "available": True,
        "total": total,
        "page": page,
        "pages": -(-total // limit),
        "lines": lines,
        "source": source,
        "entries": paged,
    }


# ── crowdsec log ──────────────────────────────────────────────────────────────

@router.get("/crowdsec")
def crowdsec_logs(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    lines: int = _DEFAULT_LINES,
    limit: int = _DEFAULT_LIMIT,
    page: int = 1,
    minutes: int = _DEFAULT_MINUTES,
    level: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """CrowdSec log — read from mounted file or via docker exec."""
    s = get_settings()
    log_path = _resolve_path(db, "log_path_crowdsec", s.crowdsec_log_path)
    container = _get_container_name(db, "crowdsec_container_name", "crowdsec")
    container_paths = [
        "/var/log/crowdsec/crowdsec.log",
        "/var/log/crowdsec.log",
    ]

    grep_terms: list[str] = []
    if search:
        grep_terms.append(search)
    if level:
        grep_terms.append(_level_grep_term(level))

    raw_lines, source = _read_log_lines(log_path, container, container_paths, lines, grep_terms)

    if not raw_lines:
        return {"available": False, "total": 0, "entries": [], "lines": lines, "source": source}

    entries = _filter_log_entries(
        raw_lines,
        cut=_cutoff(minutes),
        level_lc=level.lower() if level else None,
        search_lc=search.lower() if search else None,
    )

    limit = max(1, min(limit, 2000))
    total = len(entries)
    paged = entries[(page - 1) * limit: page * limit]
    return {
        "available": True,
        "total": total,
        "page": page,
        "pages": -(-total // limit),
        "lines": lines,
        "source": source,
        "entries": paged,
    }
