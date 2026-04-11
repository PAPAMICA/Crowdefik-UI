from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import require_superuser
from app.core.security import hash_password
from app.db import get_db
from app.models import User, UserRouterScope
from app.schemas import RouterScopeIn, UserCreateIn, UserOut

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", response_model=list[UserOut])
def list_users(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> list[User]:
    return db.query(User).order_by(User.id.asc()).all()


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreateIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> User:
    exists = db.query(User).filter(User.username == body.username).one_or_none()
    if exists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    u = User(username=body.username, password_hash=hash_password(body.password), is_superuser=body.is_superuser)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Annotated[Session, Depends(get_db)],
    actor: Annotated[User, Depends(require_superuser)],
) -> None:
    if user_id == actor.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete yourself")
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    db.delete(u)
    db.commit()


def _scopes_for_user(db: Session, user_id: int) -> list[str]:
    return [s.router_name for s in db.query(UserRouterScope).filter(UserRouterScope.user_id == user_id)]


@router.get("/users/{user_id}/scopes", response_model=list[str])
def list_scopes(
    user_id: int,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> list[str]:
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return _scopes_for_user(db, user_id)


@router.post("/users/{user_id}/scopes", response_model=list[str])
def add_scope(
    user_id: int,
    body: RouterScopeIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> list[str]:
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if u.is_superuser:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Superusers do not need scopes")
    exists = (
        db.query(UserRouterScope)
        .filter(UserRouterScope.user_id == user_id, UserRouterScope.router_name == body.router_name)
        .one_or_none()
    )
    if exists is None:
        db.add(UserRouterScope(user_id=user_id, router_name=body.router_name))
        db.commit()
    return _scopes_for_user(db, user_id)


@router.delete("/users/{user_id}/scopes/{router_name:path}", response_model=list[str])
def remove_scope(
    user_id: int,
    router_name: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> list[str]:
    row = (
        db.query(UserRouterScope)
        .filter(UserRouterScope.user_id == user_id, UserRouterScope.router_name == router_name)
        .one_or_none()
    )
    if row:
        db.delete(row)
        db.commit()
    return _scopes_for_user(db, user_id)
