"""Audit log API — read recent security actions, server-side paginated."""
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import get_db
from app.models import AuditLog, User

router = APIRouter(prefix="/admin/audit", tags=["audit"])


@router.get("")
def list_audit(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    page: int = 1,
    limit: int = 50,
    action: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    if not user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superuser required")

    limit = max(1, min(limit, 500))
    page = max(1, page)

    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    if search:
        like = f"%{search}%"
        q = q.filter(
            AuditLog.username.ilike(like) |
            AuditLog.action.ilike(like) |
            AuditLog.target.ilike(like) |
            AuditLog.detail.ilike(like)
        )

    total = q.count()
    rows = q.order_by(AuditLog.created_at.desc()).offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "pages": max(1, -(-total // limit)),
        "limit": limit,
        "rows": [
            {
                "id": r.id,
                "username": r.username,
                "action": r.action,
                "target": r.target,
                "detail": r.detail,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }
