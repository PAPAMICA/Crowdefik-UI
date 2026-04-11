import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.integrations.instance_settings import get_or_create_instance_settings, traefik_basic_password_plain

log = logging.getLogger(__name__)


def _auth(db: Session) -> tuple[str, str] | None:
    row = get_or_create_instance_settings(db)
    user = row.traefik_basic_user
    pwd = traefik_basic_password_plain(db)
    if user and pwd:
        return (user, pwd)
    return None


def _base(db: Session) -> str:
    return get_or_create_instance_settings(db).traefik_api_url.rstrip("/")


def fetch_routers_sync(db: Session) -> list[dict[str, Any]]:
    auth = _auth(db)
    url = f"{_base(db)}/api/http/routers"
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(url, auth=auth)
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("Traefik routers fetch failed (%s): %s", url, exc)
        return []


def fetch_middlewares_sync(db: Session) -> list[dict[str, Any]]:
    auth = _auth(db)
    url = f"{_base(db)}/api/http/middlewares"
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(url, auth=auth)
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("Traefik middlewares fetch failed (%s): %s", url, exc)
        return []


async def fetch_routers(db: Session) -> list[dict[str, Any]]:
    auth = _auth(db)
    url = f"{_base(db)}/api/http/routers"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, auth=auth)
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("Traefik routers fetch failed (%s): %s", url, exc)
        return []


def test_connection(db: Session) -> dict[str, Any]:
    """Return latency, version, router count — or an error detail."""
    auth = _auth(db)
    base = _base(db)
    try:
        with httpx.Client(timeout=8.0) as client:
            # Try /api/overview first (v2/v3); fall back to /api/http/routers
            r = client.get(f"{base}/api/overview", auth=auth)
            if r.status_code == 200:
                data = r.json()
                return {
                    "ok": True,
                    "url": base,
                    "version": data.get("version"),
                    "http_routers": data.get("http", {}).get("routers", {}).get("total"),
                }
            # Try routers endpoint directly
            r2 = client.get(f"{base}/api/http/routers", auth=auth)
            r2.raise_for_status()
            routers = r2.json()
            return {"ok": True, "url": base, "version": None, "http_routers": len(routers)}
    except httpx.HTTPStatusError as exc:
        return {"ok": False, "url": base, "error": f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"}
    except Exception as exc:
        return {"ok": False, "url": base, "error": str(exc)[:300]}
