from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    router_scopes: Mapped[list["UserRouterScope"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class UserRouterScope(Base):
    __tablename__ = "user_router_scopes"
    __table_args__ = (UniqueConstraint("user_id", "router_name", name="uq_user_router"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    router_name: Mapped[str] = mapped_column(String(512), index=True)

    user: Mapped["User"] = relationship(back_populates="router_scopes")


class InstanceSettings(Base):
    __tablename__ = "instance_settings"

    # NOTE: avoid Mapped[Optional[...]] here; some Python/SQLAlchemy combos crash on union introspection.
    id = mapped_column(Integer, primary_key=True, default=1)
    traefik_api_url = mapped_column(String(512), default="http://traefik:8080", nullable=False)
    traefik_basic_user = mapped_column(String(256), nullable=True)
    traefik_basic_password_enc = mapped_column(Text, nullable=True)
    crowdsec_lapi_url = mapped_column(String(512), default="http://crowdsec:8080", nullable=False)
    crowdsec_api_key_enc = mapped_column(Text, nullable=True)
    abuseipdb_api_key_enc = mapped_column(Text, nullable=True)
    # CrowdSec machine/watcher credentials (needed for /v1/alerts — bouncer key only allows /v1/decisions)
    crowdsec_machine_id = mapped_column(String(256), nullable=True)
    crowdsec_machine_pass_enc = mapped_column(Text, nullable=True)
    updated_at = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


# ──────────────────────────────────────────────
# CrowdSec data storage (rolling 7-day window)
# ──────────────────────────────────────────────

class StoredAlert(Base):
    __tablename__ = "stored_alerts"
    # Use CrowdSec numeric alert id as PK for idempotent upsert
    id = mapped_column(Integer, primary_key=True)
    scenario = mapped_column(String(512), nullable=False, default="")
    source_ip = mapped_column(String(64), index=True, nullable=True)
    source_country = mapped_column(String(8), nullable=True)
    source_lat = mapped_column(Float, nullable=True)
    source_lon = mapped_column(Float, nullable=True)
    # Target service extracted from events[*].meta http_host
    target_host = mapped_column(String(256), nullable=True, index=True)
    events_count = mapped_column(Integer, default=1, nullable=False)
    start_at = mapped_column(DateTime, nullable=True, index=True)
    stop_at = mapped_column(DateTime, nullable=True)
    raw_json = mapped_column(Text, nullable=False)
    synced_at = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class StoredDecision(Base):
    __tablename__ = "stored_decisions"
    id = mapped_column(Integer, primary_key=True)
    ip_value = mapped_column(String(256), index=True, nullable=False)
    decision_type = mapped_column(String(64), nullable=True)
    scope = mapped_column(String(64), nullable=True)
    scenario = mapped_column(String(512), nullable=True)
    duration_str = mapped_column(String(64), nullable=True)
    until = mapped_column(DateTime, nullable=True)
    raw_json = mapped_column(Text, nullable=False)
    synced_at = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class IpGeoCache(Base):
    """Persistent geolocation cache so ip-api.com is not called repeatedly."""
    __tablename__ = "ip_geo_cache"
    ip = mapped_column(String(64), primary_key=True)
    lat = mapped_column(Float, nullable=True)
    lon = mapped_column(Float, nullable=True)
    country_code = mapped_column(String(8), nullable=True)
    country = mapped_column(String(128), nullable=True)
    city = mapped_column(String(128), nullable=True)
    isp = mapped_column(String(256), nullable=True)
    updated_at = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(Base):
    """Tracks security-relevant actions performed by users."""
    __tablename__ = "audit_log"

    id = mapped_column(Integer, primary_key=True)
    user_id = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username = mapped_column(String(256), nullable=False)
    action = mapped_column(String(64), nullable=False, index=True)
    target = mapped_column(String(512), nullable=True)
    detail = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
