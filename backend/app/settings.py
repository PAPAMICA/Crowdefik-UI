from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CROWDEFIK_", env_file=".env", extra="ignore")

    app_name: str = "Crowdefik"
    database_url: str = "sqlite:////data/crowdefik.db"
    jwt_secret: str = "change-me-in-production-use-long-random-string"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24
    app_secret: str = "change-me-32-chars-minimum!!"

    traefik_custom_dir: Path = Path("/traefik-custom")
    # Override files are written directly in traefik_custom_dir (NOT a subdir)
    # so Traefik's file provider picks them up immediately via `directory: custom/`.
    # Files are named  crowdefik-<safe_router_name>.yml  to avoid collisions.
    crowdsec_middleware: str = "crowdsec@file"

    cache_ttl_seconds: int = 60 * 60 * 2
    crowdsec_cache_ttl_seconds: int = 60

    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None

    cors_origins: str = "*"


@lru_cache
def get_settings() -> Settings:
    return Settings()
