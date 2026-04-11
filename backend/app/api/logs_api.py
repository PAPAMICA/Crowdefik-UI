"""
Unified log viewer API.

Three log sources:
  GET /api/logs/access    — Traefik JSON access log (structured table)
  GET /api/logs/traefik   — Traefik application log (text/structured lines)
  GET /api/logs/crowdsec  — CrowdSec log (via docker exec or mounted file)
"""
import json as _json
import logging
import re
import subprocess
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.db import get_db
from app.models import User
from app.settings import get_settings

router = APIRouter(prefix="/logs", tags=["logs"])
log = logging.getLogger(__name__)

_MAX_TAIL = 50_000
_DEFAULT_LIMIT = 500


# ── helpers ───────────────────────────────────────────────────────────────────

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


# ── access log ────────────────────────────────────────────────────────────────

@router.get("/access")
def access_logs(
    _db: Annotated[object, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    limit: int = _DEFAULT_LIMIT,
    page: int = 1,
    host: str | None = None,
    search: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    """Traefik JSON access log — filterable, paginated."""
    s = get_settings()
    if not s.traefik_log_path or not s.traefik_log_path.exists():
        return {"available": False, "total": 0, "entries": []}

    raw_lines = _tail(s.traefik_log_path, _MAX_TAIL)
    entries: list[dict[str, Any]] = []

    search_lc = search.lower() if search else None
    host_lc = host.lower() if host else None

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
            "time": e.get("StartUTC") or e.get("time"),
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
        "entries": paged,
    }


# ── traefik app log ───────────────────────────────────────────────────────────

_TRAEFIK_LOG_RE = re.compile(
    r'time="(?P<time>[^"]+)".*level=(?P<level>\w+)\s+msg="(?P<msg>[^"]*)"'
)


def _parse_traefik_line(line: str) -> dict[str, str] | None:
    # Try JSON first
    if line.startswith("{"):
        try:
            d = _json.loads(line)
            return {
                "time": d.get("time", ""),
                "level": d.get("level", "info"),
                "msg": d.get("msg", d.get("message", "")),
                "raw": line,
            }
        except Exception:
            pass
    # Fallback: key=value text format
    m = _TRAEFIK_LOG_RE.search(line)
    if m:
        return {"time": m.group("time"), "level": m.group("level"), "msg": m.group("msg"), "raw": line}
    if line.strip():
        return {"time": "", "level": "info", "msg": line.strip(), "raw": line}
    return None


@router.get("/traefik")
def traefik_logs(
    _db: Annotated[object, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    limit: int = _DEFAULT_LIMIT,
    page: int = 1,
    level: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """Traefik application log (traefik.log). Requires CROWDEFIK_TRAEFIK_APP_LOG_PATH."""
    s = get_settings()
    if not s.traefik_app_log_path or not s.traefik_app_log_path.exists():
        return {"available": False, "total": 0, "entries": []}

    raw_lines = _tail(s.traefik_app_log_path, _MAX_TAIL)
    entries: list[dict[str, str]] = []
    search_lc = search.lower() if search else None
    level_lc = level.lower() if level else None

    for line in reversed(raw_lines):
        parsed = _parse_traefik_line(line)
        if not parsed:
            continue
        if level_lc and parsed["level"].lower() != level_lc:
            continue
        if search_lc and search_lc not in parsed["msg"].lower() and search_lc not in parsed["raw"].lower():
            continue
        entries.append(parsed)

    limit = max(1, min(limit, 2000))
    total = len(entries)
    paged = entries[(page - 1) * limit: page * limit]
    return {"available": True, "total": total, "page": page, "pages": -(-total // limit), "entries": paged}


# ── crowdsec log ──────────────────────────────────────────────────────────────

_CS_LOG_RE = re.compile(
    r'time="(?P<time>[^"]+)".*level=(?P<level>\w+)\s+msg="(?P<msg>[^"]*)"'
)


def _parse_crowdsec_line(line: str) -> dict[str, str] | None:
    if line.startswith("{"):
        try:
            d = _json.loads(line)
            return {
                "time": d.get("time", ""),
                "level": d.get("level", "info"),
                "msg": d.get("msg", d.get("message", "")),
                "raw": line,
            }
        except Exception:
            pass
    m = _CS_LOG_RE.search(line)
    if m:
        return {"time": m.group("time"), "level": m.group("level"), "msg": m.group("msg"), "raw": line}
    if line.strip():
        return {"time": "", "level": "info", "msg": line.strip(), "raw": line}
    return None


@router.get("/crowdsec")
def crowdsec_logs(
    db: Annotated[object, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    limit: int = _DEFAULT_LIMIT,
    page: int = 1,
    level: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """CrowdSec log — read from mounted file or via docker exec."""
    s = get_settings()

    raw_lines: list[str] = []

    # Option 1: mounted log file
    if s.crowdsec_log_path and s.crowdsec_log_path.exists():
        raw_lines = _tail(s.crowdsec_log_path, _MAX_TAIL)
    else:
        # Option 2: docker exec
        from app.integrations.instance_settings import get_or_create_instance_settings
        row = get_or_create_instance_settings(db)  # type: ignore[arg-type]
        container = getattr(row, "crowdsec_container_name", None) or "crowdsec"
        raw_lines = _docker_exec(container, ["tail", "-n", "2000", "/var/log/crowdsec/crowdsec.log"])
        if not raw_lines:
            # Try alternative paths
            raw_lines = _docker_exec(container, ["tail", "-n", "2000", "/var/log/crowdsec.log"])

    if not raw_lines:
        return {"available": False, "total": 0, "entries": []}

    entries: list[dict[str, str]] = []
    search_lc = search.lower() if search else None
    level_lc = level.lower() if level else None

    for line in reversed(raw_lines):
        parsed = _parse_crowdsec_line(line)
        if not parsed:
            continue
        if level_lc and parsed["level"].lower() != level_lc:
            continue
        if search_lc and search_lc not in parsed["msg"].lower() and search_lc not in parsed["raw"].lower():
            continue
        entries.append(parsed)

    limit = max(1, min(limit, 2000))
    total = len(entries)
    paged = entries[(page - 1) * limit: page * limit]
    return {"available": True, "total": total, "page": page, "pages": -(-total // limit), "entries": paged}
