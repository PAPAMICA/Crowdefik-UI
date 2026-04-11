"""Helper to write audit log entries."""
import logging
from sqlalchemy.orm import Session
from app.models import AuditLog, User

log = logging.getLogger(__name__)


def log_action(
    db: Session,
    user: User,
    action: str,
    target: str | None = None,
    detail: str | None = None,
) -> None:
    """Write a single audit entry. Silently swallows errors so it never breaks the main flow."""
    try:
        entry = AuditLog(
            user_id=user.id,
            username=user.username,
            action=action,
            target=target,
            detail=detail,
        )
        db.add(entry)
        db.commit()
    except Exception as exc:
        log.warning("Audit log write failed: %s", exc)
        db.rollback()
