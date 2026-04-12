from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.audit import log_action
from app.core.rate_limit import limiter
from app.core.security import create_access_token, verify_password
from app.db import get_db
from app.api.deps import get_current_user
from app.models import AuditLog, User
from app.schemas import LoginIn, TokenOut, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenOut)
@limiter.limit("10/minute")
def login(request: Request, body: LoginIn, db: Annotated[Session, Depends(get_db)]) -> TokenOut:
    user = db.query(User).filter(User.username == body.username).one_or_none()
    if user is None or not verify_password(body.password, user.password_hash):
        _log_failed_login(db, body.username)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(user.username, user.id, user.is_superuser)
    log_action(db, user, "login_success")
    return TokenOut(access_token=token)


def _log_failed_login(db: Session, username: str) -> None:
    """Write a failed-login audit entry without a real User object."""
    import logging
    try:
        entry = AuditLog(
            user_id=None,
            username=username,
            action="login_failed",
            target=None,
            detail="Invalid credentials",
        )
        db.add(entry)
        db.commit()
    except Exception as exc:
        logging.getLogger(__name__).warning("Audit log write failed: %s", exc)
        db.rollback()


@router.get("/me", response_model=UserOut)
def me(user: Annotated[User, Depends(get_current_user)]) -> User:
    return user
