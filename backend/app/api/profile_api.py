"""User profile API — view own profile and change password."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.security import hash_password, verify_password
from app.db import get_db
from app.models import User

router = APIRouter(prefix="/profile", tags=["profile"])


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("New password must be at least 8 characters")
        return v


class ProfileOut(BaseModel):
    id: int
    username: str
    is_superuser: bool
    scopes: list[str]

    model_config = {"from_attributes": True}


@router.get("", response_model=ProfileOut)
def get_profile(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> ProfileOut:
    scopes = [s.router_name for s in user.router_scopes]
    return ProfileOut(
        id=user.id,
        username=user.username,
        is_superuser=user.is_superuser,
        scopes=scopes,
    )


@router.put("/password")
def change_password(
    body: PasswordChangeIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, str]:
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    user.password_hash = hash_password(body.new_password)
    db.commit()
    return {"message": "Password changed successfully"}
