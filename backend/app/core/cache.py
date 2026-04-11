"""
In-memory cache with TTL and single-flight protection.

Single-flight: if multiple threads request the same key simultaneously while
the cache is cold, only ONE thread executes the factory; the others block and
receive the same result.  This prevents "thundering herd" — e.g. 3 dashboard
requests all calling the Traefik API at the same time on a cold start.
"""
import threading
import time
from typing import Any, Callable, TypeVar

from app.settings import get_settings

T = TypeVar("T")

_store: dict[str, tuple[float, Any]] = {}
_store_lock = threading.Lock()

# Per-key lock used for single-flight: only one thread rebuilds a given key.
_key_locks: dict[str, threading.Lock] = {}
_key_locks_lock = threading.Lock()


def _get_key_lock(key: str) -> threading.Lock:
    with _key_locks_lock:
        if key not in _key_locks:
            _key_locks[key] = threading.Lock()
        return _key_locks[key]


def get_cached(key: str, factory: Callable[[], T], *, ttl_seconds: int | None = None) -> T:
    """Return cached value for *key*, calling *factory()* at most once per TTL.

    Thread-safe: concurrent callers with the same cold key all block until the
    first caller finishes building the value, then all receive it immediately.
    """
    ttl = ttl_seconds if ttl_seconds is not None else get_settings().cache_ttl_seconds
    now = time.monotonic()

    # Fast path: cache hit (no per-key lock needed)
    with _store_lock:
        entry = _store.get(key)
        if entry is not None:
            exp, val = entry
            if now < exp:
                return val  # type: ignore[return-value]

    # Cache miss: acquire per-key lock so only one thread rebuilds
    key_lock = _get_key_lock(key)
    with key_lock:
        # Re-check under lock — another thread may have already rebuilt
        with _store_lock:
            entry = _store.get(key)
            if entry is not None:
                exp, val = entry
                if time.monotonic() < exp:
                    return val  # type: ignore[return-value]

        # We are the one thread responsible for rebuilding
        val = factory()
        with _store_lock:
            _store[key] = (time.monotonic() + ttl, val)
        return val  # type: ignore[return-value]


def invalidate_prefix(prefix: str) -> None:
    with _store_lock:
        keys = [k for k in _store if k.startswith(prefix)]
        for k in keys:
            del _store[k]


def invalidate_all() -> None:
    with _store_lock:
        _store.clear()
