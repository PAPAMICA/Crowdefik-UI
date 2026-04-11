from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.integrations.instance_settings import get_or_create_instance_settings, traefik_basic_password_plain


def _auth(db: Session) -> tuple[str, str] | None:
    row = get_or_create_instance_settings(db)
    user = row.traefik_basic_user
    pwd = traefik_basic_password_plain(db)
    if user and pwd:
        return (user, pwd)
    return None


async def fetch_routers(db: Session) -> list[dict[str, Any]]:
    row = get_or_create_instance_settings(db)
    base = row.traefik_api_url.rstrip("/")
    auth = _auth(db)
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(f"{base}/api/http/routers", auth=auth)
        r.raise_for_status()
        return r.json()


async def fetch_middlewares(db: Session) -> list[dict[str, Any]]:
    row = get_or_create_instance_settings(db)
    base = row.traefik_api_url.rstrip("/")
    auth = _auth(db)
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(f"{base}/api/http/middlewares", auth=auth)
        r.raise_for_status()
        return r.json()


def fetch_routers_sync(db: Session) -> list[dict[str, Any]]:
    row = get_or_create_instance_settings(db)
    base = row.traefik_api_url.rstrip("/")
    auth = _auth(db)
    with httpx.Client(timeout=30.0) as client:
        r = client.get(f"{base}/api/http/routers", auth=auth)
        r.raise_for_status()
        return r.json()


def fetch_middlewares_sync(db: Session) -> list[dict[str, Any]]:
    row = get_or_create_instance_settings(db)
    base = row.traefik_api_url.rstrip("/")
    auth = _auth(db)
    with httpx.Client(timeout=30.0) as client:
        r = client.get(f"{base}/api/http/middlewares", auth=auth)
        r.raise_for_status()
        return r.json()
