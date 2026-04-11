from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
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
    updated_at = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
