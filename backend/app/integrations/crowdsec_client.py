from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.integrations.instance_settings import crowdsec_api_key_plain, get_or_create_instance_settings


async def fetch_decisions(db: Session) -> list[dict[str, Any]]:
    key = crowdsec_api_key_plain(db)
    if not key:
        return []
    row = get_or_create_instance_settings(db)
    base = row.crowdsec_lapi_url.rstrip("/")
    headers = {"X-Api-Key": key}
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(f"{base}/v1/decisions", headers=headers)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []


async def fetch_alerts(db: Session) -> list[dict[str, Any]]:
    key = crowdsec_api_key_plain(db)
    if not key:
        return []
    row = get_or_create_instance_settings(db)
    base = row.crowdsec_lapi_url.rstrip("/")
    headers = {"X-Api-Key": key}
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(f"{base}/v1/alerts", headers=headers)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []


def fetch_decisions_sync(db: Session) -> list[dict[str, Any]]:
    key = crowdsec_api_key_plain(db)
    if not key:
        return []
    row = get_or_create_instance_settings(db)
    base = row.crowdsec_lapi_url.rstrip("/")
    headers = {"X-Api-Key": key}
    with httpx.Client(timeout=30.0) as client:
        r = client.get(f"{base}/v1/decisions", headers=headers)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []


def fetch_alerts_sync(db: Session) -> list[dict[str, Any]]:
    key = crowdsec_api_key_plain(db)
    if not key:
        return []
    row = get_or_create_instance_settings(db)
    base = row.crowdsec_lapi_url.rstrip("/")
    headers = {"X-Api-Key": key}
    with httpx.Client(timeout=30.0) as client:
        r = client.get(f"{base}/v1/alerts", headers=headers)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []


async def fetch_metrics(db: Session) -> dict[str, Any] | None:
    key = crowdsec_api_key_plain(db)
    if not key:
        return None
    row = get_or_create_instance_settings(db)
    base = row.crowdsec_lapi_url.rstrip("/")
    headers = {"X-Api-Key": key}
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(f"{base}/v1/metrics", headers=headers)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()
