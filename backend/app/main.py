import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api import admin, allowlist_api, audit_api, auth, cache_refresh, crowdsec_api, dashboard, health_api, hub_api, ip_info, logs_api, profile_api, routers_api, scenarios_api, search_api, services_api, settings_api, test_connections, traefik_api, ws
from app.core.rate_limit import limiter
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
    _fix_enrichment_flags()
    # Background CrowdSec → DB sync
    task = asyncio.create_task(_sync_loop())
    yield
    task.cancel()


async def _sync_loop() -> None:
    # Short initial delay so the app is fully ready; retry quickly if first sync fails
    await asyncio.sleep(2)
    first = True
    while True:
        try:
            await asyncio.to_thread(_do_sync)
            first = False
        except Exception as exc:
            log.warning("Background sync failed: %s", exc)
            if first:
                # Retry sooner on startup failures (CrowdSec may still be booting)
                await asyncio.sleep(10)
                continue
        await asyncio.sleep(SYNC_INTERVAL_SECONDS)


def _do_sync() -> None:
    db = SessionLocal()
    try:
        from app.core import cache as cache_mod
        from app.services.sync_service import run_full_sync
        result = run_full_sync(db)
        # Invalidate dashboard caches so the next request gets fresh data
        cache_mod.invalidate_prefix("dashboard:")
        return result
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
    (
        "SELECT crowdsec_container_name FROM instance_settings LIMIT 1",
        "ALTER TABLE instance_settings ADD COLUMN crowdsec_container_name VARCHAR(256) DEFAULT 'crowdsec'",
    ),
    (
        "SELECT log_enrichment_attempted FROM stored_alerts LIMIT 1",
        "ALTER TABLE stored_alerts ADD COLUMN log_enrichment_attempted BOOLEAN NOT NULL DEFAULT 0",
    ),
    (
        "SELECT traefik_container_name FROM instance_settings LIMIT 1",
        "ALTER TABLE instance_settings ADD COLUMN traefik_container_name VARCHAR(256) DEFAULT 'traefik'",
    ),
    (
        "SELECT abuse_score FROM ip_geo_cache LIMIT 1",
        "ALTER TABLE ip_geo_cache ADD COLUMN abuse_score INTEGER",
    ),
    (
        "SELECT abuse_total_reports FROM ip_geo_cache LIMIT 1",
        "ALTER TABLE ip_geo_cache ADD COLUMN abuse_total_reports INTEGER",
    ),
    (
        "SELECT abuse_is_tor FROM ip_geo_cache LIMIT 1",
        "ALTER TABLE ip_geo_cache ADD COLUMN abuse_is_tor BOOLEAN",
    ),
    (
        "SELECT abuse_last_reported_at FROM ip_geo_cache LIMIT 1",
        "ALTER TABLE ip_geo_cache ADD COLUMN abuse_last_reported_at VARCHAR(64)",
    ),
    (
        "SELECT abuse_domain FROM ip_geo_cache LIMIT 1",
        "ALTER TABLE ip_geo_cache ADD COLUMN abuse_domain VARCHAR(256)",
    ),
    (
        "SELECT abuse_updated_at FROM ip_geo_cache LIMIT 1",
        "ALTER TABLE ip_geo_cache ADD COLUMN abuse_updated_at DATETIME",
    ),
    (
        "SELECT log_path_access FROM instance_settings LIMIT 1",
        "ALTER TABLE instance_settings ADD COLUMN log_path_access VARCHAR(512)",
    ),
    (
        "SELECT log_path_traefik FROM instance_settings LIMIT 1",
        "ALTER TABLE instance_settings ADD COLUMN log_path_traefik VARCHAR(512)",
    ),
    (
        "SELECT log_path_crowdsec FROM instance_settings LIMIT 1",
        "ALTER TABLE instance_settings ADD COLUMN log_path_crowdsec VARCHAR(512)",
    ),
    # Allowlist table is created by create_all, but add a guard in case of partial migration
    (
        "SELECT id FROM allowlist LIMIT 1",
        "CREATE TABLE IF NOT EXISTS allowlist (id INTEGER PRIMARY KEY AUTOINCREMENT, value VARCHAR(256) UNIQUE NOT NULL, reason VARCHAR(512), created_by VARCHAR(128), expires_at DATETIME, active BOOLEAN NOT NULL DEFAULT 1, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
    ),
    # ServicePolicy table
    (
        "SELECT host FROM service_policies LIMIT 1",
        "CREATE TABLE IF NOT EXISTS service_policies (host VARCHAR(256) PRIMARY KEY, min_events_to_display INTEGER NOT NULL DEFAULT 1, auto_ban_enabled BOOLEAN NOT NULL DEFAULT 0, auto_ban_min_score INTEGER, auto_ban_min_events INTEGER, auto_ban_window_hours INTEGER NOT NULL DEFAULT 24, auto_ban_duration VARCHAR(64) NOT NULL DEFAULT '24h', muted_scenarios TEXT, notes TEXT, updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)",
    ),
    # target_host on decisions (populated by sync for fast lookup without JOIN)
    (
        "SELECT target_host FROM stored_decisions LIMIT 1",
        "ALTER TABLE stored_decisions ADD COLUMN target_host VARCHAR(256)",
    ),
]


# Idempotent SQL statements that are always safe to run (CREATE INDEX IF NOT EXISTS, etc.)
# These are executed unconditionally — they must use IF NOT EXISTS or equivalent guards.
_IDEMPOTENT_SQL: list[str] = [
    "CREATE INDEX IF NOT EXISTS ix_alert_host_synced    ON stored_alerts    (target_host, synced_at)",
    "CREATE INDEX IF NOT EXISTS ix_alert_ip_start       ON stored_alerts    (source_ip, start_at)",
    "CREATE INDEX IF NOT EXISTS ix_decision_ip_until    ON stored_decisions (ip_value, until)",
    "CREATE INDEX IF NOT EXISTS ix_decision_target_host ON stored_decisions (target_host)",
]


def _run_migrations() -> None:
    """
    Apply each migration independently so a failure on one never blocks the others.
    Each migration is: try the check query; if it fails (column/table absent) run the ALTER.

    PostgreSQL-specific: when a statement fails inside a connection, the transaction
    is left in an "aborted" state and all subsequent commands are ignored until a
    ROLLBACK is issued.  We therefore use TWO separate connections:
      1. A read-only connection to run the check query (discarded on failure).
      2. A fresh connection (clean transaction) to run the ALTER.
    This avoids the "InFailedSqlTransaction" error on PostgreSQL while remaining
    fully compatible with SQLite (which ignores rollbacks on non-transaction errors).
    """
    log.info("Running %d DB migration checks…", len(_MIGRATIONS))
    for check_sql, alter_sql in _MIGRATIONS:
        needs_alter = False
        # Step 1: probe with a dedicated connection — let it be discarded on failure
        try:
            with engine.connect() as probe:
                try:
                    probe.exec_driver_sql(check_sql)
                    # Check passed → column/table already exists, nothing to do.
                except Exception:
                    needs_alter = True
                    # Explicitly roll back so the connection is left clean
                    # (required by PostgreSQL; harmless on SQLite).
                    try:
                        probe.rollback()
                    except Exception:
                        pass
        except Exception as conn_exc:
            log.warning("Migration probe connection error for '%s': %s", alter_sql, conn_exc)
            continue

        if not needs_alter:
            continue

        # Step 2: apply the migration on a fresh, clean connection
        try:
            with engine.connect() as conn:
                try:
                    log.info("Applying migration: %s", alter_sql)
                    conn.exec_driver_sql(alter_sql)
                    conn.commit()
                    log.info("Migration applied OK: %s", alter_sql)
                except Exception as alter_exc:
                    log.warning("Migration ALTER failed (will retry on next start): %s — %s", alter_sql, alter_exc)
                    try:
                        conn.rollback()
                    except Exception:
                        pass
        except Exception as conn_exc:
            log.warning("Migration connection error for '%s': %s", alter_sql, conn_exc)

    # Always run idempotent DDL (CREATE INDEX IF NOT EXISTS, etc.)
    for sql in _IDEMPOTENT_SQL:
        try:
            with engine.connect() as conn:
                conn.exec_driver_sql(sql)
                conn.commit()
        except Exception as exc:
            log.warning("Idempotent migration failed (non-blocking): %s — %s", sql, exc)


def _fix_enrichment_flags() -> None:
    """
    Reset log_enrichment_attempted for alerts that have no target_host so they
    get a fresh correlation attempt now that the log path may be configured.
    Previously this flag could be set to True even when the log file was simply
    not found, which prevented any future retry.
    Uses ORM-level update to remain compatible with both SQLite and PostgreSQL.
    """
    from sqlalchemy import update as _update
    from app.models import StoredAlert as _SA
    try:
        with SessionLocal() as session:
            session.execute(
                _update(_SA)
                .where(_SA.target_host.is_(None))
                .where(_SA.log_enrichment_attempted == True)  # noqa: E712
                .values(log_enrichment_attempted=False)
            )
            session.commit()
    except Exception as exc:
        log.warning("Could not reset enrichment flags: %s", exc)


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

    # Configure structured JSON logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format='{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}',
    )

    app = FastAPI(
        title=settings.app_name,
        lifespan=lifespan,
        # Disable interactive docs in production (debug=false)
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    # Rate limiter state
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    if not origins:
        origins = ["*"]

    # allow_credentials=True is incompatible with wildcard origins — browsers reject it.
    # Only enable credentials when explicit origins are configured.
    allow_credentials = settings.cors_allow_credentials and origins != ["*"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
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
    app.include_router(search_api.router, prefix="/api")
    app.include_router(scenarios_api.router, prefix="/api")
    app.include_router(cache_refresh.router, prefix="/api")
    app.include_router(test_connections.router, prefix="/api")
    app.include_router(services_api.router, prefix="/api")
    app.include_router(logs_api.router, prefix="/api")
    app.include_router(ip_info.router, prefix="/api")
    app.include_router(allowlist_api.router, prefix="/api")
    app.include_router(hub_api.router, prefix="/api")
    app.include_router(hub_api.policy_router, prefix="/api")
    app.include_router(health_api.router, prefix="/api")
    app.include_router(ws.router)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
