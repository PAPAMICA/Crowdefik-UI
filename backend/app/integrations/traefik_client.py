import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.integrations.instance_settings import get_or_create_instance_settings, traefik_basic_password_plain

log = logging.getLogger(__name__)

# Aggressive timeouts so a slow/unreachable Traefik never blocks the dashboard.
# connect=2s: fail fast if the TCP handshake doesn't complete (unreachable host).
# read=6s:    allow a bit more time once connected (large router lists).
_TIMEOUT = httpx.Timeout(connect=2.0, read=6.0, write=5.0, pool=1.0)


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
        with httpx.Client(timeout=_TIMEOUT) as client:
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
        with httpx.Client(timeout=_TIMEOUT) as client:
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
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
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
        with httpx.Client(timeout=_TIMEOUT) as client:
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
        with httpx.Client(timeout=_TIMEOUT) as client:
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
        with httpx.Client(timeout=_TIMEOUT) as client:
            r = client.get(url, auth=auth)
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("Traefik services fetch failed: %s", exc)
        return []


def fetch_tls_domains(db: Session) -> list[dict[str, Any]]:
    """Extract TLS domain info from routers and check cert expiry via SSL.

    All SSL probes run concurrently (ThreadPoolExecutor) so the total wall
    time is bounded by the slowest single host, not N×timeout.
    The DB session is only used for the initial router fetch; it is not
    accessed during the (potentially slow) SSL checks.
    """
    import re
    import socket
    import ssl
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from datetime import datetime, timezone

    # Fetch routers first (uses DB) — after this the DB session is no longer needed.
    routers = fetch_routers_sync(db)

    # Build the unique (domain → router_name) map from TLS routers
    domain_router: dict[str, str] = {}
    for r in routers:
        if not r.get("tls"):
            continue
        rule = r.get("rule", "")
        for host in re.findall(r'Host\(`([^`]+)`\)', rule):
            if host not in domain_router:
                domain_router[host] = r.get("name", "")

    if not domain_router:
        return []

    # ── Probe a single host (runs in a thread pool worker) ────────────────────
    def _probe(host: str) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "domain": host,
            "router": domain_router[host],
            "expiry": None,
            "days_left": None,
            "status": "unknown",
        }
        try:
            ctx = ssl.create_default_context()
            # Use a short connect timeout (3 s) so unreachable hosts fail fast.
            with ctx.wrap_socket(
                socket.create_connection((host, 443), timeout=3),
                server_hostname=host,
            ) as conn:
                cert = conn.getpeercert()
            if cert and "notAfter" in cert:
                expiry = datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                entry["expiry"] = expiry.isoformat()
                entry["days_left"] = days_left
                entry["status"] = (
                    "critical" if days_left <= 7 else
                    "warning" if days_left <= 30 else
                    "ok"
                )
        except Exception as exc:
            log.debug("TLS check failed for %s: %s", host, exc)
            entry["status"] = "unreachable"
        return entry

    # ── Run all probes in parallel (max 20 workers) ───────────────────────────
    results: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(20, len(domain_router))) as pool:
        futures = {pool.submit(_probe, host): host for host in domain_router}
        for fut in as_completed(futures):
            try:
                entry = fut.result()
                results[entry["domain"]] = entry
            except Exception as exc:
                host = futures[fut]
                log.warning("Unexpected error probing %s: %s", host, exc)
                results[host] = {
                    "domain": host,
                    "router": domain_router[host],
                    "expiry": None,
                    "days_left": None,
                    "status": "unreachable",
                }

    return sorted(results.values(), key=lambda x: (x.get("days_left") or 9999))


def test_connection(db: Session) -> dict[str, Any]:
    """Return latency, version, router count — or an error detail."""
    auth = _auth(db)
    base = _base(db)
    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
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
