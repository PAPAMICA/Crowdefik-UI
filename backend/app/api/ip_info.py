from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import get_db
from app.integrations import abuseipdb_client, ipgeo_client
from app.models import User

router = APIRouter(prefix="/ip", tags=["ip"])


@router.get("/{ip}")
def get_ip_info(
    ip: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    geo = ipgeo_client.geolocate_ip(ip)
    abuse = abuseipdb_client.check_ip(db, ip)
    return {
        "ip": ip,
        "geo": geo,
        "abuse": abuse,
    }
