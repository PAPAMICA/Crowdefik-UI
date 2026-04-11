from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import require_superuser
from app.db import get_db
from app.integrations import abuseipdb_client, crowdsec_client, docker_svc, traefik_client
from app.models import User

router = APIRouter(prefix="/test", tags=["test"])


@router.get("/traefik")
def test_traefik(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    return traefik_client.test_connection(db)


@router.get("/crowdsec")
def test_crowdsec(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    return crowdsec_client.test_connection(db)


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
