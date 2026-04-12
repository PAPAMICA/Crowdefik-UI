from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CROWDEFIK_", env_file=".env", extra="ignore")

    app_name: str = "Crowdefik"
    database_url: str = "sqlite:////data/crowdefik.db"
    jwt_secret: str = "change-me-in-production-use-long-random-string"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 2  # 2 hours default
    app_secret: str = "change-me-32-chars-minimum!!"

    traefik_custom_dir: Path = Path("/traefik-custom")
    # Override files are written directly in traefik_custom_dir (NOT a subdir)
    # so Traefik's file provider picks them up immediately via `directory: custom/`.
    # Files are named  crowdefik-<safe_router_name>.yml  to avoid collisions.
    crowdsec_middleware: str = "crowdsec@file"

    # Path to the Traefik JSON access.log inside the container.
    traefik_log_path: Path | None = None

    # Path to the Traefik application log (traefik.log, text format).
    traefik_app_log_path: Path | None = None

    # Path to the CrowdSec log file inside the container.
    crowdsec_log_path: Path | None = None

    cache_ttl_seconds: int = 60 * 60 * 2
    crowdsec_cache_ttl_seconds: int = 60

    # Optional Redis URL for distributed / persistent caching.
    # When set, the cache backend switches to Redis; otherwise the default
    # in-memory dict is used (suitable for single-instance deployments).
    # Example: redis://crowdefik-redis:6379/0
    redis_url: str | None = None

    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None

    cors_origins: str = "*"
    # When cors_origins is a specific list (not *), credentials can be allowed.
    cors_allow_credentials: bool = False

    # Set to true to enable /docs and /redoc Swagger UI (disable in production).
    debug: bool = False

    # Structured log level: DEBUG, INFO, WARNING, ERROR
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
