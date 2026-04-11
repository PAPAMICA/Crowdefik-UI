import json
import logging
from typing import Any

import docker
from docker.errors import DockerException, NotFound

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


def _cscli(container_name: str, args: list[str]) -> dict[str, Any]:
    """Run a cscli command inside a container and return parsed JSON output."""
    try:
        c = _client()
    except DockerException as exc:
        return {"ok": False, "error": f"Docker connect failed: {exc}"}
    try:
        container = c.containers.get(container_name)
    except NotFound:
        return {"ok": False, "error": f"Container '{container_name}' not found"}
    except DockerException as exc:
        return {"ok": False, "error": str(exc)}
    try:
        result = container.exec_run(["cscli"] + args + ["-o", "json"])
        raw = result.output.decode("utf-8", errors="replace").strip()
        if result.exit_code != 0:
            return {"ok": False, "error": raw or f"cscli exited with code {result.exit_code}"}
        data = json.loads(raw) if raw else []
        return {"ok": True, "data": data}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def cscli_list_bouncers(container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli(container_name, ["bouncers", "list"])


def cscli_add_bouncer(name: str, container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli(container_name, ["bouncers", "add", name])


def cscli_delete_bouncer(name: str, container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli(container_name, ["bouncers", "delete", name])


def cscli_list_machines(container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli(container_name, ["machines", "list"])


def cscli_add_machine(machine_id: str, password: str, container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli(container_name, ["machines", "add", machine_id, "--password", password, "--force"])


def cscli_delete_machine(machine_id: str, container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli(container_name, ["machines", "delete", machine_id])


def cscli_validate_machine(machine_id: str, container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli(container_name, ["machines", "validate", machine_id])


def cscli_metrics(container_name: str = "crowdsec") -> dict[str, Any]:
    """Run `cscli metrics -o json` and return parsed output."""
    return _cscli(container_name, ["metrics"])


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
