from typing import Any

import docker
from docker.errors import DockerException


def _client() -> docker.DockerClient:
    return docker.from_env()


def list_traefik_containers() -> list[dict[str, Any]]:
    try:
        c = _client()
    except DockerException:
        return []
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
