from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import get_db
from app.integrations import abuseipdb_client, ipgeo_client
from app.models import IpGeoCache, User

router = APIRouter(prefix="/ip", tags=["ip"])

# Re-fetch abuse score after this many days (scores change over time).
_ABUSE_TTL_DAYS = 7
# Re-fetch geo after this many days (IPs rarely change region).
_GEO_TTL_DAYS = 30


def _geo_stale(row: IpGeoCache) -> bool:
    return (datetime.utcnow() - row.updated_at) > timedelta(days=_GEO_TTL_DAYS)


def _abuse_stale(row: IpGeoCache) -> bool:
    if row.abuse_updated_at is None:
        return True
    return (datetime.utcnow() - row.abuse_updated_at) > timedelta(days=_ABUSE_TTL_DAYS)


@router.get("/{ip}")
def get_ip_info(
    ip: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return geo + abuse data for *ip*.

    Strategy (fastest first):
      1. Read from IpGeoCache (DB).
      2. If geo is missing or stale (>30d), call ip-api.com and update cache.
      3. If abuse is missing or stale (>7d), call AbuseIPDB and update cache.
    External APIs are only called when the cached data is absent or expired.
    """
    row = db.query(IpGeoCache).filter(IpGeoCache.ip == ip).first()
    dirty = False

    # ── Geo ───────────────────────────────────────────────────────────────────
    if row is None or _geo_stale(row):
        geo_data = ipgeo_client.geolocate_ip(ip)
        if geo_data:
            if row is None:
                row = IpGeoCache(ip=ip)
            row.lat = geo_data.get("lat")
            row.lon = geo_data.get("lon")
            row.country_code = geo_data.get("countryCode")
            row.country = geo_data.get("country")
            row.city = geo_data.get("city")
            row.isp = geo_data.get("isp")
            row.updated_at = datetime.utcnow()
            dirty = True
        elif row is None:
            # geo failed and nothing cached — create a skeleton row so abuse can still be stored
            row = IpGeoCache(ip=ip, updated_at=datetime.utcnow())
            dirty = True

    geo: dict[str, Any] | None = None
    if row and (row.country or row.city):
        geo = {
            "country":     row.country,
            "countryCode": row.country_code,
            "city":        row.city,
            "isp":         row.isp,
            "lat":         row.lat,
            "lon":         row.lon,
        }

    # ── Abuse ─────────────────────────────────────────────────────────────────
    abuse: dict[str, Any] | None = None

    if row and not _abuse_stale(row) and row.abuse_score is not None:
        # Serve from cache — no external call needed
        abuse = {
            "abuseConfidenceScore": row.abuse_score,
            "totalReports":         row.abuse_total_reports,
            "isTor":                row.abuse_is_tor,
            "lastReportedAt":       row.abuse_last_reported_at,
            "domain":               row.abuse_domain,
            "countryCode":          row.country_code,
            "isp":                  row.isp,
        }
    else:
        # Cache miss or stale — call AbuseIPDB
        fresh = abuseipdb_client.check_ip(db, ip)
        if fresh:
            abuse = fresh
            if row is None:
                row = IpGeoCache(ip=ip, updated_at=datetime.utcnow())
            row.abuse_score          = fresh.get("abuseConfidenceScore")
            row.abuse_total_reports  = fresh.get("totalReports")
            row.abuse_is_tor         = fresh.get("isTor")
            row.abuse_last_reported_at = fresh.get("lastReportedAt")
            row.abuse_domain         = fresh.get("domain")
            row.abuse_updated_at     = datetime.utcnow()
            dirty = True

    # ── Persist ───────────────────────────────────────────────────────────────
    if dirty and row is not None:
        db.merge(row)
        db.commit()

    return {"ip": ip, "geo": geo, "abuse": abuse}
