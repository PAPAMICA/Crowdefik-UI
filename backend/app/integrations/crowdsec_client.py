import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.integrations.instance_settings import crowdsec_api_key_plain, get_or_create_instance_settings

log = logging.getLogger(__name__)


def _headers(db: Session) -> dict[str, str] | None:
    key = crowdsec_api_key_plain(db)
    if not key:
        return None
    return {"X-Api-Key": key}


def _base(db: Session) -> str:
    return get_or_create_instance_settings(db).crowdsec_lapi_url.rstrip("/")


def fetch_decisions_sync(db: Session) -> list[dict[str, Any]]:
    h = _headers(db)
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


def fetch_alerts_sync(db: Session) -> list[dict[str, Any]]:
    h = _headers(db)
    if not h:
        return []
    url = f"{_base(db)}/v1/alerts"
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(url, headers=h)
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, list) else []
    except Exception as exc:
        log.warning("CrowdSec alerts fetch failed (%s): %s", url, exc)
        return []


async def fetch_decisions(db: Session) -> list[dict[str, Any]]:
    h = _headers(db)
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


async def fetch_alerts(db: Session) -> list[dict[str, Any]]:
    h = _headers(db)
    if not h:
        return []
    url = f"{_base(db)}/v1/alerts"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, headers=h)
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, list) else []
    except Exception as exc:
        log.warning("CrowdSec alerts fetch failed (%s): %s", url, exc)
        return []


async def fetch_metrics(db: Session) -> dict[str, Any] | None:
    h = _headers(db)
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


def delete_decision(db: Session, decision_id: int) -> dict[str, Any]:
    """Delete (unban) a decision by its CrowdSec ID."""
    h = _headers(db)
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


def test_connection(db: Session) -> dict[str, Any]:
    """Check LAPI reachability + API key validity."""
    h = _headers(db)
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
