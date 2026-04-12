"""
Allowlist API — manage local IP/CIDR allowlist.

IPs/CIDRs on the allowlist are never auto-banned by the sync service.
The sync service also checks against this list before issuing any manual-triggered ban.
"""
import ipaddress
import json as _json
import math
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, validator
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.audit import log_action
from app.db import get_db
from app.models import Allowlist, User

router = APIRouter(prefix="/crowdsec/allowlist", tags=["allowlist"])


# ── Schemas ────────────────────────────────────────────────────────────────────

class AllowlistIn(BaseModel):
    value: str           # IP or CIDR
    reason: str | None = None
    expires_hours: int | None = None  # None = permanent

    @validator("value")
    def validate_value(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("value must not be empty")
        # Accept IP, CIDR, or 2-letter country code
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            pass
        if len(v) == 2 and v.isalpha():
            return v.upper()
        raise ValueError(f"Invalid IP, CIDR or country code: {v!r}")


class AllowlistBulkIn(BaseModel):
    entries: list[str]   # list of IPs/CIDRs (one per line)
    reason: str | None = None
    expires_hours: int | None = None


class AllowlistOut(BaseModel):
    id: int
    value: str
    reason: str | None
    created_by: str | None
    expires_at: str | None
    active: bool
    created_at: str
    expired: bool

    class Config:
        from_attributes = True


def _to_out(row: Allowlist) -> dict[str, Any]:
    now = datetime.utcnow()
    expired = bool(row.expires_at and row.expires_at < now)
    return {
        "id": row.id,
        "value": row.value,
        "reason": row.reason,
        "created_by": row.created_by,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "active": row.active and not expired,
        "expired": expired,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

def is_ip_allowlisted(db: Session, ip: str) -> bool:
    """Return True if the given IP is covered by an active allowlist entry."""
    now = datetime.utcnow()
    rows = db.query(Allowlist).filter(
        Allowlist.active == True,  # noqa: E712
    ).all()
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False

    for row in rows:
        if row.expires_at and row.expires_at < now:
            continue
        try:
            if "/" in row.value:
                if ip_obj in ipaddress.ip_network(row.value, strict=False):
                    return True
            else:
                if ipaddress.ip_address(row.value) == ip_obj:
                    return True
        except ValueError:
            continue
    return False


def get_allowlisted_ips(db: Session) -> set[str]:
    """Return all active allowlist values (IPs and CIDRs)."""
    now = datetime.utcnow()
    return {
        r.value for r in db.query(Allowlist).filter(Allowlist.active == True).all()  # noqa: E712
        if not (r.expires_at and r.expires_at < now)
    }


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("")
def list_allowlist(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
    page: int = 1,
    limit: int = 50,
    show_expired: bool = False,
) -> dict[str, Any]:
    """List all allowlist entries, optionally including expired ones."""
    limit = max(1, min(limit, 200))
    q = db.query(Allowlist)
    if not show_expired:
        now = datetime.utcnow()
        q = q.filter(
            (Allowlist.expires_at == None) | (Allowlist.expires_at > now)  # noqa: E711
        )
    q = q.order_by(Allowlist.created_at.desc())
    total = q.count()
    rows = q.offset((page - 1) * limit).limit(limit).all()
    return {
        "total": total,
        "page": page,
        "pages": math.ceil(total / limit) if total else 0,
        "entries": [_to_out(r) for r in rows],
    }


@router.post("/check")
def check_ip(
    body: dict[str, str],
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Check whether a given IP is covered by an active allowlist entry."""
    ip = (body.get("ip") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip required")

    now = datetime.utcnow()
    rows = db.query(Allowlist).filter(Allowlist.active == True).all()  # noqa: E712
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "protected": False, "entry": None}

    for row in rows:
        if row.expires_at and row.expires_at < now:
            continue
        try:
            matched = False
            if "/" in row.value:
                matched = ip_obj in ipaddress.ip_network(row.value, strict=False)
            else:
                matched = ipaddress.ip_address(row.value) == ip_obj
            if matched:
                return {
                    "ip": ip,
                    "protected": True,
                    "entry": {
                        "id": row.id,
                        "reason": row.reason,
                        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                    },
                }
        except ValueError:
            continue

    return {"ip": ip, "protected": False, "entry": None}


@router.post("", status_code=status.HTTP_201_CREATED)
def add_entry(
    body: AllowlistIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Add an IP/CIDR to the allowlist (superuser only)."""
    if not user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required")

    existing = db.query(Allowlist).filter(Allowlist.value == body.value).first()
    if existing:
        # Re-activate if it was deactivated or expired
        existing.active = True
        existing.reason = body.reason
        existing.expires_at = (
            datetime.utcnow() + timedelta(hours=body.expires_hours)
            if body.expires_hours else None
        )
        existing.created_by = user.username
        db.commit()
        log_action(db, user, "allowlist_add", target=body.value, detail=body.reason)
        return _to_out(existing)

    expires_at = None
    if body.expires_hours:
        expires_at = datetime.utcnow() + timedelta(hours=body.expires_hours)

    row = Allowlist(
        value=body.value,
        reason=body.reason,
        created_by=user.username,
        expires_at=expires_at,
        active=True,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log_action(db, user, "allowlist_add", target=body.value, detail=body.reason)
    return _to_out(row)


@router.post("/bulk", status_code=status.HTTP_201_CREATED)
def bulk_add(
    body: AllowlistBulkIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Add multiple IPs/CIDRs at once. Invalid entries are skipped with a warning."""
    if not user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required")

    from datetime import timedelta
    expires_at = datetime.utcnow() + timedelta(hours=body.expires_hours) if body.expires_hours else None

    added, skipped, errors = 0, 0, []
    for raw in body.entries:
        v = raw.strip()
        if not v:
            continue
        try:
            AllowlistIn(value=v, reason=body.reason)
        except Exception as exc:
            errors.append(f"{v}: {exc}")
            continue

        existing = db.query(Allowlist).filter(Allowlist.value == v).first()
        if existing:
            existing.active = True
            existing.reason = body.reason
            existing.expires_at = expires_at
            skipped += 1
        else:
            db.add(Allowlist(value=v, reason=body.reason, created_by=user.username,
                             expires_at=expires_at, active=True))
            added += 1

    db.commit()
    log_action(db, user, "allowlist_bulk", detail=f"added={added} reactivated={skipped} errors={len(errors)}")
    return {"added": added, "reactivated": skipped, "errors": errors}


@router.delete("/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_entry(
    entry_id: int,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> None:
    """Remove an allowlist entry (superuser only)."""
    if not user.is_superuser:
        raise HTTPException(status_code=403, detail="Superuser required")
    row = db.get(Allowlist, entry_id)
    if not row:
        raise HTTPException(status_code=404, detail="Entry not found")
    target = row.value
    db.delete(row)
    db.commit()
    log_action(db, user, "allowlist_remove", target=target)
