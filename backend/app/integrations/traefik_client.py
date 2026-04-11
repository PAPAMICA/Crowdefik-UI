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


def fetch_overview_sync(db: Session) -> dict[str, Any]:
    auth = _auth(db)
    base = _base(db)
    result: dict[str, Any] = {"version": None, "http": {}, "tcp": {}, "udp": {}, "features": []}
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(f"{base}/api/overview", auth=auth)
            if r.status_code == 200:
                result.update(r.json())
            rv = client.get(f"{base}/api/version", auth=auth)
            if rv.status_code == 200:
                result["version_detail"] = rv.json()
    except Exception as exc:
        log.warning("Traefik overview fetch failed: %s", exc)
    return result


def fetch_entrypoints_sync(db: Session) -> list[dict[str, Any]]:
    auth = _auth(db)
    url = f"{_base(db)}/api/entrypoints"
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(url, auth=auth)
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("Traefik entrypoints fetch failed: %s", exc)
        return []


def fetch_services_sync(db: Session) -> list[dict[str, Any]]:
    auth = _auth(db)
    url = f"{_base(db)}/api/http/services"
    try:
        with httpx.Client(timeout=10.0) as client:
            r = client.get(url, auth=auth)
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("Traefik services fetch failed: %s", exc)
        return []


def fetch_tls_domains(db: Session) -> list[dict[str, Any]]:
    """Extract TLS domain info from routers and check cert expiry via SSL."""
    import ssl
    import socket

    routers = fetch_routers_sync(db)
    domains: dict[str, dict[str, Any]] = {}

    for r in routers:
        tls = r.get("tls")
        if not tls:
            continue
        rule = r.get("rule", "")
        # Extract hosts from rule like Host(`foo.example.com`)
        import re
        hosts = re.findall(r'Host\(`([^`]+)`\)', rule)
        for host in hosts:
            if host in domains:
                continue
            entry: dict[str, Any] = {
                "domain": host,
                "router": r.get("name", ""),
                "expiry": None,
                "days_left": None,
                "status": "unknown",
            }
            try:
                ctx = ssl.create_default_context()
                conn = ctx.wrap_socket(
                    socket.create_connection((host, 443), timeout=5),
                    server_hostname=host,
                )
                cert = conn.getpeercert()
                conn.close()
                if cert and "notAfter" in cert:
                    from datetime import datetime, timezone
                    expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    entry["expiry"] = expiry.isoformat()
                    entry["days_left"] = days_left
                    if days_left <= 7:
                        entry["status"] = "critical"
                    elif days_left <= 30:
                        entry["status"] = "warning"
                    else:
                        entry["status"] = "ok"
            except Exception as exc:
                log.debug("TLS check failed for %s: %s", host, exc)
                entry["status"] = "unreachable"
            domains[host] = entry

    return sorted(domains.values(), key=lambda x: (x.get("days_left") or 9999))


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
