from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import admin, auth, cache_refresh, crowdsec_api, dashboard, routers_api, settings_api, test_connections, ws
from app.core.security import hash_password
from app.db import SessionLocal, engine
from app.models import Base, User
from app.settings import get_settings


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    _bootstrap_admin_if_needed()
    yield


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
    app.include_router(cache_refresh.router, prefix="/api")
    app.include_router(test_connections.router, prefix="/api")
    app.include_router(ws.router)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
