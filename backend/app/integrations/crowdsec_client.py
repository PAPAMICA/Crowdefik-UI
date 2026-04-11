"""
CrowdSec LAPI client.

Two authentication modes:
  - Bouncer API key  (X-Api-Key)  → /v1/decisions only
  - Watcher JWT      (Bearer)     → /v1/alerts + /v1/decisions

If machine credentials are configured, alerts use the watcher JWT.
If only the bouncer key is set, alerts are unavailable (LAPI returns 401).
"""
import logging
import threading
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.integrations.instance_settings import (
    crowdsec_api_key_plain,
    crowdsec_machine_password_plain,
    get_or_create_instance_settings,
)

log = logging.getLogger(__name__)

# ── JWT cache (module-level, thread-safe) ─────────────────────
_jwt_lock = threading.Lock()
_jwt_cache: dict[str, tuple[str, datetime]] = {}   # key → (token, expires_at)
_JWT_BUFFER_SECONDS = 60   # renew this many seconds before expiry


def _base(db: Session) -> str:
    return get_or_create_instance_settings(db).crowdsec_lapi_url.rstrip("/")


def _bouncer_headers(db: Session) -> dict[str, str] | None:
    key = crowdsec_api_key_plain(db)
    if not key:
        return None
    return {"X-Api-Key": key}


# ── Watcher (machine) JWT ─────────────────────────────────────

def _watcher_jwt(db: Session) -> str | None:
    """Return a valid watcher JWT, refreshing if needed. Returns None if not configured."""
    s = get_or_create_instance_settings(db)
    machine_id = s.crowdsec_machine_id or ""
    password = crowdsec_machine_password_plain(db) or ""
    if not machine_id or not password:
        return None

    cache_key = f"{_base(db)}|{machine_id}"
    with _jwt_lock:
        cached = _jwt_cache.get(cache_key)
        if cached:
            token, expires_at = cached
            if datetime.utcnow() < expires_at - timedelta(seconds=_JWT_BUFFER_SECONDS):
                return token

    # Authenticate
    url = f"{_base(db)}/v1/watchers/login"
    try:
        with httpx.Client(timeout=8.0) as client:
            r = client.post(url, json={"machine_id": machine_id, "password": password})
            r.raise_for_status()
            data = r.json()
            token = data.get("token") or data.get("access_token")
            expire_str = data.get("expire")
            if expire_str:
                try:
                    expires_at = datetime.fromisoformat(expire_str.replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    expires_at = datetime.utcnow() + timedelta(hours=1)
            else:
                expires_at = datetime.utcnow() + timedelta(hours=1)

            with _jwt_lock:
                _jwt_cache[cache_key] = (token, expires_at)
            log.info("CrowdSec watcher JWT obtained (expires %s)", expires_at)
            return token
    except Exception as exc:
        log.warning("CrowdSec watcher login failed (%s): %s", url, exc)
        return None


def _watcher_headers(db: Session) -> dict[str, str] | None:
    token = _watcher_jwt(db)
    if not token:
        return None
    return {"Authorization": f"Bearer {token}"}


def invalidate_jwt_cache(db: Session) -> None:
    s = get_or_create_instance_settings(db)
    cache_key = f"{_base(db)}|{s.crowdsec_machine_id or ''}"
    with _jwt_lock:
        _jwt_cache.pop(cache_key, None)


# ── Decisions (bouncer key is enough) ────────────────────────

def fetch_decisions_sync(db: Session) -> list[dict[str, Any]]:
    h = _bouncer_headers(db)
    if not h:
        return []
    url = f"{_base(db)}/v1/decisions"
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(url, headers=h)
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, list) else []
    except Exception as exc:
        log.warning("CrowdSec decisions fetch failed (%s): %s", url, exc)
        return []


# ── Alerts (requires watcher JWT) ────────────────────────────

def fetch_alerts_sync(db: Session, since_hours: int = 168) -> list[dict[str, Any]]:
    """Fetch alerts from CrowdSec LAPI (requires watcher/machine credentials).

    Args:
        since_hours: Fetch alerts from the last N hours (default 168 = 7 days).
    """
    # Try watcher JWT first
    h = _watcher_headers(db)
    if not h:
        # Fall back to bouncer key — will 401 on most LAPI installs
        h = _bouncer_headers(db)
    if not h:
        return []
    # CrowdSec LAPI `since` param accepts Go duration strings like "168h"
    url = f"{_base(db)}/v1/alerts?since={since_hours}h&limit=2000"
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.get(url, headers=h)
            if r.status_code == 401:
                log.warning(
                    "CrowdSec alerts 401 — bouncer keys cannot read alerts. "
                    "Add machine credentials in Crowdefik Settings to enable alert access."
                )
                return []
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, list) else []
    except Exception as exc:
        log.warning("CrowdSec alerts fetch failed (%s): %s", url, exc)
        return []


# ── Async variants (used by WebSocket) ───────────────────────

async def fetch_decisions(db: Session) -> list[dict[str, Any]]:
    h = _bouncer_headers(db)
    if not h:
        return []
    url = f"{_base(db)}/v1/decisions"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, headers=h)
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, list) else []
    except Exception as exc:
        log.warning("CrowdSec decisions fetch failed (%s): %s", url, exc)
        return []


async def fetch_alerts(db: Session, since_hours: int = 168) -> list[dict[str, Any]]:
    import asyncio
    # JWT refresh is synchronous; run in thread to avoid blocking event loop
    h = await asyncio.to_thread(_watcher_headers, db)
    if not h:
        h = _bouncer_headers(db)
    if not h:
        return []
    url = f"{_base(db)}/v1/alerts?since={since_hours}h&limit=2000"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(url, headers=h)
            if r.status_code == 401:
                return []
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, list) else []
    except Exception as exc:
        log.warning("CrowdSec alerts fetch failed (%s): %s", url, exc)
        return []


async def fetch_metrics(db: Session) -> dict[str, Any] | None:
    h = _bouncer_headers(db)
    if not h:
        return None
    url = f"{_base(db)}/v1/metrics"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, headers=h)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("CrowdSec metrics fetch failed (%s): %s", url, exc)
        return None


# ── Add decision (manual ban) ─────────────────────────────────

def add_decision(db: Session, ip: str, duration: str = "24h", reason: str = "manual", decision_type: str = "ban") -> dict[str, Any]:
    """Add a new CrowdSec decision (manual ban). Requires watcher credentials."""
    h = _watcher_headers(db)
    if not h:
        return {"ok": False, "error": "Watcher credentials required to add decisions"}
    base = _base(db)
    payload = {
        "decisions": [{
            "duration": duration,
            "origin": "crowdefik",
            "scenario": reason,
            "scope": "Ip",
            "type": decision_type,
            "value": ip,
        }]
    }
    try:
        with httpx.Client(timeout=8.0) as client:
            r = client.post(f"{base}/v1/decisions", headers=h, json=payload)
            r.raise_for_status()
            return {"ok": True, "ip": ip, "duration": duration, "type": decision_type}
    except httpx.HTTPStatusError as exc:
        return {"ok": False, "error": f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300]}


# ── Bouncers & Machines ───────────────────────────────────────

def get_bouncers(db: Session) -> list[dict[str, Any]]:
    """Fetch list of registered bouncers. Requires watcher credentials."""
    h = _watcher_headers(db)
    if not h:
        return []
    url = f"{_base(db)}/v1/bouncers"
    try:
        with httpx.Client(timeout=8.0) as client:
            r = client.get(url, headers=h)
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, list) else []
    except Exception as exc:
        log.warning("CrowdSec bouncers fetch failed: %s", exc)
        return []


def get_machines(db: Session) -> list[dict[str, Any]]:
    """Fetch list of registered machines/watchers. Requires watcher credentials."""
    h = _watcher_headers(db)
    if not h:
        return []
    url = f"{_base(db)}/v1/watchers"
    try:
        with httpx.Client(timeout=8.0) as client:
            r = client.get(url, headers=h)
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, list) else []
    except Exception as exc:
        log.warning("CrowdSec machines fetch failed: %s", exc)
        return []


# ── Unban ─────────────────────────────────────────────────────

def delete_decision(db: Session, decision_id: int) -> dict[str, Any]:
    """Delete (unban) a decision by its CrowdSec ID."""
    h = _bouncer_headers(db)
    base = _base(db)
    if not h:
        return {"ok": False, "error": "No API key configured"}
    try:
        with httpx.Client(timeout=8.0) as client:
            r = client.delete(f"{base}/v1/decisions/{decision_id}", headers=h)
            r.raise_for_status()
            return {"ok": True, "id": decision_id}
    except httpx.HTTPStatusError as exc:
        return {"ok": False, "error": f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300]}


# ── Connection test ───────────────────────────────────────────

def test_connection(db: Session) -> dict[str, Any]:
    """Check LAPI reachability + API key validity."""
    h = _bouncer_headers(db)
    base = _base(db)
    if not h:
        return {"ok": False, "url": base, "error": "No API key configured"}
    try:
        with httpx.Client(timeout=8.0) as client:
            r = client.get(f"{base}/v1/decisions", headers=h)
            if r.status_code in (200, 204):
                decisions = r.json() if r.status_code == 200 else []
                count = len(decisions) if isinstance(decisions, list) else 0
                return {"ok": True, "url": base, "active_decisions": count}
            r.raise_for_status()
            return {"ok": True, "url": base}
    except httpx.HTTPStatusError as exc:
        return {"ok": False, "url": base, "error": f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"}
    except Exception as exc:
        return {"ok": False, "url": base, "error": str(exc)[:300]}


def test_watcher_connection(db: Session) -> dict[str, Any]:
    """Test machine/watcher credentials by fetching alerts."""
    base = _base(db)
    s = get_or_create_instance_settings(db)
    if not s.crowdsec_machine_id:
        return {"ok": False, "url": base, "error": "No machine ID configured"}
    invalidate_jwt_cache(db)   # force fresh login
    h = _watcher_headers(db)
    if not h:
        return {"ok": False, "url": base, "error": "Authentication failed — check machine ID and password"}
    try:
        with httpx.Client(timeout=8.0) as client:
            r = client.get(f"{base}/v1/alerts?limit=1", headers=h)
            r.raise_for_status()
            return {"ok": True, "url": base, "machine_id": s.crowdsec_machine_id}
    except httpx.HTTPStatusError as exc:
        return {"ok": False, "url": base, "error": f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"}
    except Exception as exc:
        return {"ok": False, "url": base, "error": str(exc)[:300]}
