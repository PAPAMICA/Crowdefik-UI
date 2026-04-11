import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.integrations.instance_settings import get_or_create_instance_settings
from app.core.crypto import decrypt_str

log = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2"


def _api_key(db: Session) -> str | None:
    row = get_or_create_instance_settings(db)
    enc = row.abuseipdb_api_key_enc
    if not enc:
        return None
    try:
        return decrypt_str(enc)
    except Exception:
        return None


def check_ip(db: Session, ip: str) -> dict[str, Any] | None:
    key = _api_key(db)
    if not key:
        return None
    try:
        with httpx.Client(timeout=httpx.Timeout(connect=3.0, read=6.0, write=5.0, pool=1.0)) as client:
            r = client.get(
                f"{ABUSEIPDB_URL}/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
            )
            r.raise_for_status()
            data = r.json()
            return data.get("data")
    except Exception as exc:
        log.warning("AbuseIPDB check failed for %s: %s", ip, exc)
        return None


def test_connection(db: Session) -> dict[str, Any]:
    key = _api_key(db)
    if not key:
        return {"ok": False, "error": "No AbuseIPDB API key configured"}
    try:
        # check a known safe IP (Cloudflare DNS)
        result = check_ip(db, "1.1.1.1")
        if result is None:
            return {"ok": False, "error": "Request failed"}
        return {
            "ok": True,
            "test_ip": "1.1.1.1",
            "abuse_score": result.get("abuseConfidenceScore"),
            "country": result.get("countryCode"),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300]}
