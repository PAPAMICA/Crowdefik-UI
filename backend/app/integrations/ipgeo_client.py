import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)


def geolocate_ip(ip: str) -> dict[str, Any] | None:
    """Free geolocation via ip-api.com (no key, max 45 req/min)."""
    try:
        with httpx.Client(timeout=3.0) as client:
            r = client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,regionName,city,lat,lon,isp,org,as,query"},
            )
            r.raise_for_status()
            data = r.json()
            if data.get("status") == "success":
                return data
    except Exception as exc:
        log.warning("ip-api.com geolocate failed for %s: %s", ip, exc)
    return None


def batch_geolocate(ips: list[str]) -> list[dict[str, Any]]:
    """Batch geolocation for up to 100 IPs."""
    if not ips:
        return []
    try:
        body = [{"query": ip} for ip in ips[:100]]
        params = {"fields": "status,country,countryCode,regionName,city,lat,lon,isp,org,query"}
        with httpx.Client(timeout=15.0) as client:
            r = client.post("http://ip-api.com/batch", json=body, params=params)
            r.raise_for_status()
            return [d for d in r.json() if d.get("status") == "success"]
    except Exception as exc:
        log.warning("ip-api.com batch geolocate failed: %s", exc)
        return []
