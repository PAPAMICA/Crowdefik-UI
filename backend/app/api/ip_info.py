from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import get_db
from app.integrations import abuseipdb_client, ipgeo_client
from app.models import IpGeoCache, User

router = APIRouter(prefix="/ip", tags=["ip"])


@router.get("/{ip}")
def get_ip_info(
    ip: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    # Check DB geo cache first to avoid slow external API calls for known IPs.
    cached = db.query(IpGeoCache).filter(IpGeoCache.ip == ip).first()
    if cached:
        geo: dict[str, Any] | None = {
            "country": cached.country,
            "countryCode": cached.country_code,
            "city": cached.city,
            "isp": cached.isp,
            "lat": cached.lat,
            "lon": cached.lon,
        }
    else:
        geo = ipgeo_client.geolocate_ip(ip)
        if geo:
            entry = IpGeoCache(
                ip=ip,
                lat=geo.get("lat"),
                lon=geo.get("lon"),
                country_code=geo.get("countryCode"),
                country=geo.get("country"),
                city=geo.get("city"),
                isp=geo.get("isp"),
                updated_at=datetime.utcnow(),
            )
            db.merge(entry)
            db.commit()

    abuse = abuseipdb_client.check_ip(db, ip)
    return {"ip": ip, "geo": geo, "abuse": abuse}
