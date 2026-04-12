import threading
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import require_superuser
from app.db import SessionLocal, get_db
from app.integrations import abuseipdb_client, crowdsec_client, docker_svc, traefik_client
from app.models import User

router = APIRouter(prefix="/test", tags=["test"])


def _fire_sync_in_background() -> None:
    """Trigger a sync in a daemon thread so the test endpoint returns immediately."""
    def _run() -> None:
        db = SessionLocal()
        try:
            from app.core import cache as cache_mod
            from app.services.sync_service import run_full_sync
            run_full_sync(db)
            cache_mod.invalidate_prefix("dashboard:")
            cache_mod.invalidate_prefix("traefik:")
        except Exception:
            pass
        finally:
            db.close()

    t = threading.Thread(target=_run, daemon=True)
    t.start()


@router.get("/traefik")
def test_traefik(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    result = traefik_client.test_connection(db)
    if result.get("ok"):
        _fire_sync_in_background()
    return result


@router.get("/crowdsec")
def test_crowdsec(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    result = crowdsec_client.test_connection(db)
    if result.get("ok"):
        _fire_sync_in_background()
    return result


@router.get("/docker")
def test_docker(
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    return docker_svc.test_connection()


@router.get("/abuseipdb")
def test_abuseipdb(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    return abuseipdb_client.test_connection(db)


@router.get("/crowdsec-watcher")
def test_crowdsec_watcher(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    result = crowdsec_client.test_watcher_connection(db)
    if result.get("ok"):
        _fire_sync_in_background()
    return result
