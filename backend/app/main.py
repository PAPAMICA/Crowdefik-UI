import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import admin, audit_api, auth, cache_refresh, crowdsec_api, dashboard, ip_info, profile_api, routers_api, settings_api, test_connections, traefik_api, ws
from app.core.security import hash_password
from app.db import SessionLocal, engine
from app.models import Base, User
from app.settings import get_settings

log = logging.getLogger(__name__)

SYNC_INTERVAL_SECONDS = 300  # 5 minutes


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Run raw-SQL migrations FIRST (before SQLAlchemy ORM touches any table)
    # so that all columns exist by the time create_all / model queries run.
    _run_migrations()
    Base.metadata.create_all(bind=engine)
    _bootstrap_admin_if_needed()
    # Background CrowdSec → DB sync
    task = asyncio.create_task(_sync_loop())
    yield
    task.cancel()


async def _sync_loop() -> None:
    # Short initial delay so the app is fully ready
    await asyncio.sleep(5)
    while True:
        try:
            await asyncio.to_thread(_do_sync)
        except Exception as exc:
            log.warning("Background sync failed: %s", exc)
        await asyncio.sleep(SYNC_INTERVAL_SECONDS)


def _do_sync() -> None:
    db = SessionLocal()
    try:
        from app.services.sync_service import run_full_sync
        run_full_sync(db)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Lightweight column-level migrations (no Alembic needed for this project).
# Each entry is idempotent: ADD COLUMN is only executed when the column is
# absent, so it is safe to run on every startup.
# ---------------------------------------------------------------------------
_MIGRATIONS: list[tuple[str, str]] = [
    # (check_sql, alter_sql)
    (
        "SELECT abuseipdb_api_key_enc FROM instance_settings LIMIT 1",
        "ALTER TABLE instance_settings ADD COLUMN abuseipdb_api_key_enc TEXT",
    ),
    (
        "SELECT crowdsec_machine_id FROM instance_settings LIMIT 1",
        "ALTER TABLE instance_settings ADD COLUMN crowdsec_machine_id VARCHAR(256)",
    ),
    (
        "SELECT crowdsec_machine_pass_enc FROM instance_settings LIMIT 1",
        "ALTER TABLE instance_settings ADD COLUMN crowdsec_machine_pass_enc TEXT",
    ),
    (
        "SELECT target_host FROM stored_alerts LIMIT 1",
        "ALTER TABLE stored_alerts ADD COLUMN target_host VARCHAR(256)",
    ),
]


def _run_migrations() -> None:
    """
    Apply each migration independently so a failure on one never blocks the others.
    Each migration is: try the check query; if it fails (column/table absent) run the ALTER.
    Both the check and the alter are individually try/excepted so the loop always completes.
    """
    log.info("Running %d DB migration checks…", len(_MIGRATIONS))
    for check_sql, alter_sql in _MIGRATIONS:
        # Use a fresh connection per migration so a failed transaction doesn't
        # leave the connection in an error state for subsequent migrations.
        try:
            with engine.connect() as conn:
                try:
                    conn.exec_driver_sql(check_sql)
                    # Check passed → column already exists, nothing to do.
                except Exception:
                    try:
                        log.info("Applying migration: %s", alter_sql)
                        conn.exec_driver_sql(alter_sql)
                        conn.commit()
                        log.info("Migration applied OK: %s", alter_sql)
                    except Exception as alter_exc:
                        log.warning("Migration ALTER failed (will retry on next start): %s — %s", alter_sql, alter_exc)
        except Exception as conn_exc:
            log.warning("Migration connection error for '%s': %s", alter_sql, conn_exc)


def _bootstrap_admin_if_needed() -> None:
    settings = get_settings()
    if not settings.bootstrap_admin_username or not settings.bootstrap_admin_password:
        return
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        db.add(
            User(
                username=settings.bootstrap_admin_username,
                password_hash=hash_password(settings.bootstrap_admin_password),
                is_superuser=True,
            )
        )
        db.commit()
    finally:
        db.close()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, lifespan=lifespan)

    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    if not origins:
        origins = ["*"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth.router, prefix="/api")
    app.include_router(routers_api.router, prefix="/api")
    app.include_router(dashboard.router, prefix="/api")
    app.include_router(crowdsec_api.router, prefix="/api")
    app.include_router(settings_api.router, prefix="/api")
    app.include_router(admin.router, prefix="/api")
    app.include_router(audit_api.router, prefix="/api")
    app.include_router(profile_api.router, prefix="/api")
    app.include_router(traefik_api.router, prefix="/api")
    app.include_router(cache_refresh.router, prefix="/api")
    app.include_router(test_connections.router, prefix="/api")
    app.include_router(ip_info.router, prefix="/api")
    app.include_router(ws.router)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
