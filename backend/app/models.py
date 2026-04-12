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
    # Docker container name for cscli management (default: "crowdsec")
    crowdsec_container_name = mapped_column(String(256), nullable=True, default="crowdsec")
    # Docker container name for reading Traefik logs via docker exec (default: "traefik")
    traefik_container_name = mapped_column(String(256), nullable=True, default="traefik")
    # Log file paths — override env vars at runtime without container restart
    log_path_access = mapped_column(String(512), nullable=True)   # Traefik access log (JSON)
    log_path_traefik = mapped_column(String(512), nullable=True)  # Traefik app log
    log_path_crowdsec = mapped_column(String(512), nullable=True) # CrowdSec log
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
    # Set to True once we have tried Traefik log correlation (success or not).
    # Prevents re-reading the log file on every sync for unresolvable WAF alerts.
    log_enrichment_attempted = mapped_column(Boolean, default=False, nullable=False)
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
    """Persistent cache for geolocation (ip-api.com) and abuse score (AbuseIPDB)."""
    __tablename__ = "ip_geo_cache"
    ip = mapped_column(String(64), primary_key=True)
    # Geolocation — ip-api.com
    lat = mapped_column(Float, nullable=True)
    lon = mapped_column(Float, nullable=True)
    country_code = mapped_column(String(8), nullable=True)
    country = mapped_column(String(128), nullable=True)
    city = mapped_column(String(128), nullable=True)
    isp = mapped_column(String(256), nullable=True)
    updated_at = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    # AbuseIPDB — stored alongside geo to avoid repeated external calls
    abuse_score = mapped_column(Integer, nullable=True)
    abuse_total_reports = mapped_column(Integer, nullable=True)
    abuse_is_tor = mapped_column(Boolean, nullable=True)
    abuse_last_reported_at = mapped_column(String(64), nullable=True)
    abuse_domain = mapped_column(String(256), nullable=True)
    abuse_updated_at = mapped_column(DateTime, nullable=True)


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


class Allowlist(Base):
    """Local allowlist — IPs/CIDRs that should never be banned."""
    __tablename__ = "allowlist"

    id = mapped_column(Integer, primary_key=True, autoincrement=True)
    value = mapped_column(String(256), unique=True, index=True, nullable=False)  # IP or CIDR
    reason = mapped_column(String(512), nullable=True)
    created_by = mapped_column(String(128), nullable=True)
    expires_at = mapped_column(DateTime, nullable=True)   # None = permanent
    active = mapped_column(Boolean, default=True, nullable=False)
    created_at = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class ServicePolicy(Base):
    """Per-service security policy — controls display filters and auto-ban behaviour."""
    __tablename__ = "service_policies"

    host = mapped_column(String(256), primary_key=True)
    # Display filter
    min_events_to_display = mapped_column(Integer, default=1, nullable=False)
    # Auto-ban (triggered by sync_service when thresholds are exceeded)
    auto_ban_enabled = mapped_column(Boolean, default=False, nullable=False)
    auto_ban_min_score = mapped_column(Integer, nullable=True)    # AbuseIPDB score threshold
    auto_ban_min_events = mapped_column(Integer, nullable=True)   # events count within window
    auto_ban_window_hours = mapped_column(Integer, default=24, nullable=False)  # rolling window
    auto_ban_duration = mapped_column(String(64), default="24h", nullable=False)
    # Muted scenarios — JSON list of scenario names to suppress for this service
    muted_scenarios = mapped_column(Text, nullable=True)
    # Admin notes
    notes = mapped_column(Text, nullable=True)
    updated_at = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
