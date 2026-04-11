import logging
from typing import Any

import docker
from docker.errors import DockerException

log = logging.getLogger(__name__)


def _client() -> docker.DockerClient:
    return docker.from_env()


def list_traefik_containers() -> list[dict[str, Any]]:
    try:
        c = _client()
    except DockerException as exc:
        log.warning("Docker connect failed: %s", exc)
        return []
    try:
        out: list[dict[str, Any]] = []
        for container in c.containers.list(all=False):
            labels = container.labels or {}
            if labels.get("traefik.enable", "").lower() != "true":
                continue
            out.append(
                {
                    "id": container.short_id,
                    "name": container.name.lstrip("/"),
                    "image": container.image.tags[0] if container.image.tags else container.image.short_id,
                    "labels": labels,
                }
            )
        return out
    except DockerException as exc:
        log.warning("Docker list containers failed: %s", exc)
        return []


def test_connection() -> dict[str, Any]:
    """Return Docker daemon version or error."""
    try:
        c = _client()
        info = c.version()
        return {
            "ok": True,
            "version": info.get("Version"),
            "api_version": info.get("ApiVersion"),
            "os": info.get("Os"),
            "arch": info.get("Arch"),
        }
    except DockerException as exc:
        return {"ok": False, "error": str(exc)[:300]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300]}
