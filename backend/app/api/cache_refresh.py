from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.core import cache as cache_mod
from app.models import User

router = APIRouter(tags=["cache"])


@router.post("/cache/refresh")
def refresh_cache(_: Annotated[User, Depends(get_current_user)]) -> dict[str, bool]:
    cache_mod.invalidate_all()
    return {"ok": True}
