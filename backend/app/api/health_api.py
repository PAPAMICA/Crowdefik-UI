"""Health and readiness probes."""
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db

router = APIRouter(prefix="/health", tags=["health"])
log = logging.getLogger(__name__)


def _check_db(db: Session) -> dict[str, Any]:
    try:
        db.execute(text("SELECT 1"))
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _check_redis() -> dict[str, Any]:
    try:
        from app.settings import get_settings
        settings = get_settings()
        if not settings.redis_url:
            return {"ok": True, "note": "not configured — using in-memory cache"}
        import redis as redis_lib
        r = redis_lib.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        r.ping()
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _check_crowdsec(db: Session) -> dict[str, Any]:
    try:
        from app.integrations.instance_settings import get_or_create_instance_settings
        from app.core import crypto
        row = get_or_create_instance_settings(db)
        lapi_url = getattr(row, "crowdsec_lapi_url", None) or ""
        api_key_enc = getattr(row, "crowdsec_api_key_enc", None) or ""
        if not lapi_url:
            return {"ok": False, "error": "not configured"}
        api_key = crypto.decrypt_str(api_key_enc) if api_key_enc else ""
        import httpx
        resp = httpx.get(
            f"{lapi_url.rstrip('/')}/v1/alerts?limit=1",
            headers={"X-Api-Key": api_key} if api_key else {},
            timeout=3.0,
        )
        return {"ok": resp.status_code < 500, "status_code": resp.status_code}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@router.get("/ready")
def readiness(db: Annotated[Session, Depends(get_db)]) -> JSONResponse:
    """Readiness probe — returns 503 if any critical dependency is unhealthy."""
    checks: dict[str, Any] = {
        "db": _check_db(db),
        "redis": _check_redis(),
        "crowdsec": _check_crowdsec(db),
    }
    # Only DB is considered critical for service readiness
    ok = checks["db"]["ok"]
    return JSONResponse({"ok": ok, "checks": checks}, status_code=200 if ok else 503)
