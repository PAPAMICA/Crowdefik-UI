import time
from typing import Any, Callable, TypeVar

from app.settings import get_settings

T = TypeVar("T")

_store: dict[str, tuple[float, Any]] = {}


def get_cached(key: str, factory: Callable[[], T], *, ttl_seconds: int | None = None) -> T:
    ttl = ttl_seconds if ttl_seconds is not None else get_settings().cache_ttl_seconds
    now = time.monotonic()
    if key in _store:
        exp, val = _store[key]
        if now < exp:
            return val  # type: ignore[return-value]
    val = factory()
    _store[key] = (now + ttl, val)
    return val


def invalidate_prefix(prefix: str) -> None:
    keys = [k for k in _store if k.startswith(prefix)]
    for k in keys:
        del _store[k]


def invalidate_all() -> None:
    _store.clear()
