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


def _get_container(container_name: str) -> tuple[Any | None, dict[str, Any] | None]:
    """Return (container, error_dict). One of the two is always None."""
    try:
        c = _client()
    except DockerException as exc:
        return None, {"ok": False, "error": f"Docker connect failed: {exc}"}
    try:
        return c.containers.get(container_name), None
    except NotFound:
        return None, {"ok": False, "error": f"Container '{container_name}' not found"}
    except DockerException as exc:
        return None, {"ok": False, "error": str(exc)}


def _exec(container_name: str, cmd: list[str]) -> dict[str, Any]:
    """Run *cmd* in *container_name* and return {ok, output/error}.

    Captures both stdout and stderr so that messages written to stderr
    (common in cscli info/warning lines) are not silently dropped.
    Exit code 0 → ok=True.  Non-zero → ok=False.
    """
    container, err = _get_container(container_name)
    if err:
        return err
    try:
        result = container.exec_run(cmd, stderr=True, demux=False)
        raw = (result.output or b"").decode("utf-8", errors="replace").strip()
        if result.exit_code != 0:
            return {"ok": False, "error": raw or f"Command exited with code {result.exit_code}"}
        return {"ok": True, "output": raw}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _cscli_json(container_name: str, args: list[str]) -> dict[str, Any]:
    """Run a cscli command that is expected to return JSON output (-o json).

    Handles all edge cases:
    - Empty output → treated as empty list
    - Non-JSON output (logfmt) with exit_code 0 → treated as success with raw text
    - Non-zero exit code → error
    """
    container, err = _get_container(container_name)
    if err:
        return err
    try:
        result = container.exec_run(["cscli"] + args + ["-o", "json"], stderr=True, demux=False)
        raw = (result.output or b"").decode("utf-8", errors="replace").strip()
        if result.exit_code != 0:
            return {"ok": False, "error": raw or f"cscli exited with code {result.exit_code}"}
        if not raw:
            return {"ok": True, "data": []}
        try:
            data = json.loads(raw)
            return {"ok": True, "data": data}
        except json.JSONDecodeError:
            # cscli wrote non-JSON (e.g. logfmt progress lines) but exited successfully.
            # Some cscli versions ignore -o json for certain sub-commands.
            log.debug("cscli %s returned non-JSON output (exit 0): %s", args, raw[:200])
            return {"ok": True, "data": [], "output": raw}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _cscli_cmd(container_name: str, args: list[str]) -> dict[str, Any]:
    """Run a cscli command where only the exit code matters (install/remove/update).

    Does NOT pass -o json because some cscli versions write progress to stderr
    (not captured by JSON mode) and may produce mixed output.
    Just returns ok=True if exit code is 0.
    """
    result = _exec(container_name, ["cscli"] + args)
    return result


def cscli_delete_decision(decision_id: int, container_name: str = "crowdsec") -> dict[str, Any]:
    """Delete a CrowdSec decision by ID using cscli (bypasses REST API auth issues)."""
    return _cscli_cmd(container_name, ["decisions", "delete", "--id", str(decision_id)])


def cscli_delete_decision_by_ip(ip: str, container_name: str = "crowdsec") -> dict[str, Any]:
    """Delete all CrowdSec decisions for an IP using cscli."""
    return _cscli_cmd(container_name, ["decisions", "delete", "--ip", ip])


def cscli_list_bouncers(container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli_json(container_name, ["bouncers", "list"])


def cscli_add_bouncer(name: str, container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli_json(container_name, ["bouncers", "add", name])


def cscli_delete_bouncer(name: str, container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli_cmd(container_name, ["bouncers", "delete", name])


def cscli_list_machines(container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli_json(container_name, ["machines", "list"])


def cscli_add_machine(machine_id: str, password: str, container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli_cmd(container_name, ["machines", "add", machine_id, "--password", password, "--force"])


def cscli_delete_machine(machine_id: str, container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli_cmd(container_name, ["machines", "delete", machine_id])


def cscli_validate_machine(machine_id: str, container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli_cmd(container_name, ["machines", "validate", machine_id])


def cscli_metrics(container_name: str = "crowdsec") -> dict[str, Any]:
    """Run `cscli metrics -o json` and return parsed output."""
    return _cscli_json(container_name, ["metrics"])


# ── Hub / Scenarios / Collections ─────────────────────────────────────────────

def cscli_hub_update(container_name: str = "crowdsec") -> dict[str, Any]:
    """Update the hub index (cscli hub update). No JSON output expected."""
    return _exec(container_name, ["cscli", "hub", "update"])


def cscli_list_scenarios(container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli_json(container_name, ["scenarios", "list"])


def cscli_install_scenario(name: str, container_name: str = "crowdsec") -> dict[str, Any]:
    """Install a new scenario (not yet installed)."""
    return _cscli_cmd(container_name, ["scenarios", "install", name, "--force"])


def cscli_upgrade_scenario(name: str, container_name: str = "crowdsec") -> dict[str, Any]:
    """Upgrade an already-installed scenario to its latest hub version.

    Runs hub update first to refresh the index, then upgrades the specific item.
    Falls back to install --force if upgrade reports it is not installed.
    """
    # Refresh hub index so cscli knows about newer versions
    hub_res = _exec(container_name, ["cscli", "hub", "update"])
    if not hub_res["ok"]:
        log.warning("hub update failed before upgrading scenario %s: %s", name, hub_res.get("error"))

    result = _cscli_cmd(container_name, ["scenarios", "upgrade", name])
    if not result["ok"]:
        # Some cscli versions require install --force to update
        result = _cscli_cmd(container_name, ["scenarios", "install", name, "--force"])
    return result


def cscli_remove_scenario(name: str, container_name: str = "crowdsec") -> dict[str, Any]:
    """Remove a scenario. Only checks exit code — no JSON output expected."""
    return _cscli_cmd(container_name, ["scenarios", "remove", name, "--purge"])


def cscli_list_collections(container_name: str = "crowdsec") -> dict[str, Any]:
    return _cscli_json(container_name, ["collections", "list"])


def cscli_install_collection(name: str, container_name: str = "crowdsec") -> dict[str, Any]:
    """Install a new collection (not yet installed)."""
    return _cscli_cmd(container_name, ["collections", "install", name, "--force"])


def cscli_upgrade_collection(name: str, container_name: str = "crowdsec") -> dict[str, Any]:
    """Upgrade an already-installed collection to its latest hub version.

    Runs hub update first to refresh the index, then upgrades the specific item.
    Falls back to install --force if upgrade reports it is not installed.
    """
    hub_res = _exec(container_name, ["cscli", "hub", "update"])
    if not hub_res["ok"]:
        log.warning("hub update failed before upgrading collection %s: %s", name, hub_res.get("error"))

    result = _cscli_cmd(container_name, ["collections", "upgrade", name])
    if not result["ok"]:
        result = _cscli_cmd(container_name, ["collections", "install", name, "--force"])
    return result


def cscli_remove_collection(name: str, container_name: str = "crowdsec") -> dict[str, Any]:
    """Remove a collection. Only checks exit code — no JSON output expected."""
    return _cscli_cmd(container_name, ["collections", "remove", name, "--purge"])


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
