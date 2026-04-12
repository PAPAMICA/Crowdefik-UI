"""
Cache backend with Redis support and in-memory fallback.

Architecture
------------
* When ``CROWDEFIK_REDIS_URL`` is set the cache uses Redis (``redis-py``).
  - TTL is handled natively by Redis (``SETEX`` / ``EXPIRE``).
  - Values are JSON-serialised so they survive process restarts.
  - Multiple processes / workers share the same cache automatically.

* When Redis is not configured (default for local dev / single-instance
  without Redis) the original in-memory dict with single-flight protection
  is used — zero extra dependencies, zero configuration.

Public API (unchanged from the previous in-memory-only implementation)
-----------------------------------------------------------------------
  get_cached(key, factory, *, ttl_seconds=None) -> T
  set_value(key, value, ttl_seconds=None)
  invalidate_prefix(prefix)
  invalidate_all()
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import date, datetime
from typing import Any, Callable, TypeVar

from app.settings import get_settings

log = logging.getLogger(__name__)
T = TypeVar("T")

# ---------------------------------------------------------------------------
# JSON serialiser that handles types not natively supported by json.dumps
# ---------------------------------------------------------------------------

class _Encoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return {"__dt__": obj.isoformat()}
        if isinstance(obj, date):
            return {"__date__": obj.isoformat()}
        return super().default(obj)


def _decode_hook(d: dict) -> Any:
    if "__dt__" in d:
        return datetime.fromisoformat(d["__dt__"])
    if "__date__" in d:
        return date.fromisoformat(d["__date__"])
    return d


def _dumps(value: Any) -> str:
    return json.dumps(value, cls=_Encoder)


def _loads(raw: str) -> Any:
    return json.loads(raw, object_hook=_decode_hook)


# ---------------------------------------------------------------------------
# Redis backend (lazy-initialised)
# ---------------------------------------------------------------------------

_redis_client: Any | None = None   # redis.Redis or None
_redis_init_lock = threading.Lock()


def _get_redis() -> Any | None:
    """Return a connected Redis client, or None if Redis is not configured."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    with _redis_init_lock:
        if _redis_client is not None:          # double-checked locking
            return _redis_client
        url = get_settings().redis_url
        if not url:
            return None
        try:
            import redis as _redis_lib
            client = _redis_lib.from_url(url, decode_responses=True, socket_timeout=2)
            client.ping()
            _redis_client = client
            log.info("Cache backend: Redis at %s", url)
        except Exception as exc:
            log.warning("Redis unavailable (%s) — falling back to in-memory cache", exc)
            _redis_client = None
        return _redis_client


# ---------------------------------------------------------------------------
# In-memory fallback (single-flight, thread-safe)
# ---------------------------------------------------------------------------

_store: dict[str, tuple[float, Any]] = {}
_store_lock = threading.Lock()
_key_locks: dict[str, threading.Lock] = {}
_key_locks_lock = threading.Lock()


def _get_key_lock(key: str) -> threading.Lock:
    with _key_locks_lock:
        if key not in _key_locks:
            _key_locks[key] = threading.Lock()
        return _key_locks[key]


def _mem_get(key: str) -> tuple[bool, Any]:
    """Return (hit, value) from the in-memory store."""
    with _store_lock:
        entry = _store.get(key)
        if entry is not None:
            exp, val = entry
            if time.monotonic() < exp:
                return True, val
    return False, None


def _mem_set(key: str, value: Any, ttl: int) -> None:
    with _store_lock:
        _store[key] = (time.monotonic() + ttl, value)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_cached(key: str, factory: Callable[[], T], *, ttl_seconds: int | None = None) -> T:
    """Return cached value for *key*, calling *factory()* at most once per TTL.

    Thread-safe.  If Redis is configured it is tried first; the in-memory
    store is used as a hot layer otherwise (and as a fallback if Redis fails
    mid-request).
    """
    ttl = ttl_seconds if ttl_seconds is not None else get_settings().cache_ttl_seconds
    r = _get_redis()

    # ── Redis path ────────────────────────────────────────────────────────
    if r is not None:
        try:
            raw = r.get(key)
            if raw is not None:
                return _loads(raw)  # type: ignore[return-value]
        except Exception as exc:
            log.warning("Redis GET failed for %r: %s", key, exc)
            r = None  # fall through to in-memory

    if r is not None:
        # Cache miss — build value and store in Redis
        # We still use a per-key in-process lock for single-flight protection
        # so parallel workers don't all call factory() simultaneously.
        key_lock = _get_key_lock(key)
        with key_lock:
            try:
                raw = r.get(key)
                if raw is not None:
                    return _loads(raw)  # type: ignore[return-value]
            except Exception:
                pass
            val = factory()
            try:
                r.setex(key, ttl, _dumps(val))
            except Exception as exc:
                log.warning("Redis SETEX failed for %r: %s", key, exc)
        return val  # type: ignore[return-value]

    # ── In-memory fallback path ───────────────────────────────────────────
    hit, val = _mem_get(key)
    if hit:
        return val  # type: ignore[return-value]

    key_lock = _get_key_lock(key)
    with key_lock:
        hit, val = _mem_get(key)
        if hit:
            return val  # type: ignore[return-value]
        val = factory()
        _mem_set(key, val, ttl)
        return val  # type: ignore[return-value]


def set_value(key: str, value: Any, ttl_seconds: int | None = None) -> None:
    """Store a pre-computed value directly in the cache.

    Thread-safe.  Writes to Redis when available, always writes to the
    in-memory store so callers in the same process have an instant hot hit.
    """
    ttl = ttl_seconds if ttl_seconds is not None else get_settings().cache_ttl_seconds
    r = _get_redis()
    if r is not None:
        try:
            r.setex(key, ttl, _dumps(value))
        except Exception as exc:
            log.warning("Redis SETEX failed for %r: %s", key, exc)
    # Always populate in-memory too (instant hot hit for this process)
    _mem_set(key, value, ttl)


def invalidate_prefix(prefix: str) -> None:
    """Delete all cache entries whose key starts with *prefix*."""
    r = _get_redis()
    if r is not None:
        try:
            # SCAN is non-blocking; KEYS would block large keyspaces
            cursor = 0
            pattern = f"{prefix}*"
            while True:
                cursor, keys = r.scan(cursor, match=pattern, count=100)
                if keys:
                    r.delete(*keys)
                if cursor == 0:
                    break
        except Exception as exc:
            log.warning("Redis SCAN/DEL failed for prefix %r: %s", prefix, exc)
    # Always clean in-memory store
    with _store_lock:
        to_delete = [k for k in _store if k.startswith(prefix)]
        for k in to_delete:
            del _store[k]


def invalidate_all() -> None:
    """Flush the entire cache."""
    r = _get_redis()
    if r is not None:
        try:
            r.flushdb(asynchronous=True)
        except Exception as exc:
            log.warning("Redis FLUSHDB failed: %s", exc)
    with _store_lock:
        _store.clear()
