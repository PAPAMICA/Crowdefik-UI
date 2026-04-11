"""
Unified log viewer API.

Three log sources:
  GET /api/logs/access    — Traefik JSON access log (structured table)
  GET /api/logs/traefik   — Traefik application log (text/structured lines)
  GET /api/logs/crowdsec  — CrowdSec log (via docker exec or mounted file)

All endpoints support:
  minutes (int, default 20): only return entries from the last N minutes.
                              Pass 0 to disable the time filter.
"""
import json as _json
import logging
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import get_db
from app.models import User
from app.settings import get_settings

router = APIRouter(prefix="/logs", tags=["logs"])
log = logging.getLogger(__name__)

_MAX_TAIL = 50_000
_DEFAULT_LIMIT = 500
_DEFAULT_MINUTES = 20

# Conservative upper bound on log lines per minute for adaptive tail sizing.
# Access logs can be dense; app logs are sparse — we use the higher value and
# cap at _MAX_TAIL so "All" mode never reads more than 50 k lines.
_LINES_PER_MINUTE_ACCESS = 300   # up to 300 req/min
_LINES_PER_MINUTE_APP    = 100   # traefik/crowdsec app logs


def _adaptive_tail(minutes: int, lines_per_minute: int, minimum: int = 2_000) -> int:
    """Return how many lines to tail given a time window."""
    if minutes <= 0:
        return _MAX_TAIL
    return min(_MAX_TAIL, max(minimum, minutes * lines_per_minute))


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
    # Try common logfmt variants without timezone
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


# ── I/O helpers ───────────────────────────────────────────────────────────────

def _tail(path: Path, n: int) -> list[str]:
    """Read last *n* lines from *path* efficiently."""
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


def _docker_exec(container: str, cmd: list[str]) -> list[str]:
    """Run a command inside *container* and return stdout lines."""
    try:
        result = subprocess.run(
            ["docker", "exec", container] + cmd,
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.splitlines()
    except Exception as exc:
        log.warning("docker exec %s %s: %s", container, cmd, exc)
        return []


def _get_container_name(db: Session, field: str, default: str) -> str:
    """Read a container name from InstanceSettings, falling back to *default*."""
    from app.integrations.instance_settings import get_or_create_instance_settings
    row = get_or_create_instance_settings(db)
    return getattr(row, field, None) or default


# ── access log ────────────────────────────────────────────────────────────────

@router.get("/access")
def access_logs(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    limit: int = _DEFAULT_LIMIT,
    page: int = 1,
    minutes: int = _DEFAULT_MINUTES,
    host: str | None = None,
    search: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Traefik JSON access log — filterable, paginated, time-windowed."""
    s = get_settings()
    if not s.traefik_log_path or not s.traefik_log_path.exists():
        return {"available": False, "total": 0, "entries": [], "minutes": minutes}

    n_lines = _adaptive_tail(minutes, _LINES_PER_MINUTE_ACCESS)
    raw_lines = _tail(s.traefik_log_path, n_lines)
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
                # Log is reversed (newest first); once we see an entry older than
                # the cutoff, all following entries will be older too.
                break

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
    return {
        "available": True,
        "total": total,
        "page": page,
        "pages": -(-total // limit),
        "minutes": minutes,
        "entries": paged,
    }


# ── generic structured-log parser & endpoint factory ─────────────────────────

_LOG_RE = re.compile(
    r'time="(?P<time>[^"]+)".*level=(?P<level>\w+)\s+msg="(?P<msg>[^"]*)"'
)


def _parse_log_line(line: str) -> dict[str, str] | None:
    """Parse a single Traefik/CrowdSec log line (JSON or logfmt)."""
    if line.startswith("{"):
        try:
            d = _json.loads(line)
            return {
                "time": d.get("time", ""),
                "level": (d.get("level") or "info").lower(),
                "msg": d.get("msg", d.get("message", "")),
                "raw": line,
            }
        except Exception:
            pass
    m = _LOG_RE.search(line)
    if m:
        return {
            "time": m.group("time"),
            "level": m.group("level").lower(),
            "msg": m.group("msg"),
            "raw": line,
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
    entries: list[dict[str, str]] = []
    for line in reversed(raw_lines):
        parsed = _parse_log_line(line)
        if not parsed:
            continue
        if cut:
            dt = _parse_log_time(parsed["time"])
            if dt and dt < cut:
                break  # older than window — stop (reversed order)
        if level_lc and parsed["level"] != level_lc:
            continue
        if search_lc and search_lc not in parsed["msg"].lower() and search_lc not in parsed["raw"].lower():
            continue
        entries.append(parsed)
    return entries


# ── traefik app log ───────────────────────────────────────────────────────────

@router.get("/traefik")
def traefik_logs(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    limit: int = _DEFAULT_LIMIT,
    page: int = 1,
    minutes: int = _DEFAULT_MINUTES,
    level: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """Traefik application log — file or docker exec fallback."""
    s = get_settings()

    raw_lines: list[str] = []
    source = "unavailable"
    n_lines = _adaptive_tail(minutes, _LINES_PER_MINUTE_APP)

    if s.traefik_app_log_path and s.traefik_app_log_path.exists():
        raw_lines = _tail(s.traefik_app_log_path, n_lines)
        source = "file"
    else:
        # Fallback: docker exec into the Traefik container
        container = _get_container_name(db, "traefik_container_name", "traefik")
        docker_n = str(min(n_lines, 5000))
        raw_lines = _docker_exec(container, ["tail", "-n", docker_n, "/var/log/traefik/traefik.log"])
        if not raw_lines:
            raw_lines = _docker_exec(container, ["tail", "-n", docker_n, "/var/log/traefik.log"])
        if not raw_lines:
            raw_lines = _docker_exec(container, ["sh", "-c", "cat /var/log/traefik/traefik.log 2>/dev/null || cat /tmp/traefik.log 2>/dev/null || true"])
        if raw_lines:
            source = "docker"

    if not raw_lines:
        return {"available": False, "total": 0, "entries": [], "minutes": minutes, "source": source}

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
        "minutes": minutes,
        "source": source,
        "entries": paged,
    }


# ── crowdsec log ──────────────────────────────────────────────────────────────

@router.get("/crowdsec")
def crowdsec_logs(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    limit: int = _DEFAULT_LIMIT,
    page: int = 1,
    minutes: int = _DEFAULT_MINUTES,
    level: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """CrowdSec log — read from mounted file or via docker exec."""
    s = get_settings()

    raw_lines: list[str] = []
    source = "unavailable"
    n_lines = _adaptive_tail(minutes, _LINES_PER_MINUTE_APP)

    if s.crowdsec_log_path and s.crowdsec_log_path.exists():
        raw_lines = _tail(s.crowdsec_log_path, n_lines)
        source = "file"
    else:
        container = _get_container_name(db, "crowdsec_container_name", "crowdsec")
        docker_n = str(min(n_lines, 5000))
        raw_lines = _docker_exec(container, ["tail", "-n", docker_n, "/var/log/crowdsec/crowdsec.log"])
        if not raw_lines:
            raw_lines = _docker_exec(container, ["tail", "-n", docker_n, "/var/log/crowdsec.log"])
        if raw_lines:
            source = "docker"

    if not raw_lines:
        return {"available": False, "total": 0, "entries": [], "minutes": minutes, "source": source}

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
        "minutes": minutes,
        "source": source,
        "entries": paged,
    }
