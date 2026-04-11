"""
Traefik file-provider override for CrowdSec toggle.

Strategy:
  - ONE YAML file per router, stored in {traefik_custom_dir}/crowdefik-overrides/
  - The file contains a high-priority router that either:
      * Includes  crowdsec@file middleware  → "enabled by override"
      * Has NO middlewares                 → "disabled by override"
  - No override file → state is determined by Docker labels alone.
  - The override router references the original Docker service via cross-provider
    syntax (e.g. myapp@docker), so traffic is always forwarded correctly.

States returned by override_state():
  "on"   – override file exists WITH crowdsec@file
  "off"  – override file exists WITHOUT crowdsec@file
  "none" – no override file
"""

import re
from pathlib import Path
from typing import Literal

import yaml

from app.settings import Settings

OverrideState = Literal["on", "off", "none"]


# ──────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────

def _safe_name(router_name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", router_name.replace("@", "-at-"))
    return s.strip("-")[:180] or "router"


def _override_dir(settings: Settings) -> Path:
    # Write directly in the Traefik file-provider root so that `directory: custom/`
    # picks up changes immediately — no subdirectory needed.
    d = settings.traefik_custom_dir
    d.mkdir(parents=True, exist_ok=True)
    return d


def _override_path(settings: Settings, router_name: str) -> Path:
    # Prefix  crowdefik-  avoids collisions with user's own config files
    return _override_dir(settings) / f"crowdefik-{_safe_name(router_name)}.yml"


def _ensure_cross_provider_service(service: str, router_name: str) -> str:
    """
    If the service name has no provider suffix, infer it from the router provider.
    Traefik Docker routers typically have service = 'svcname@docker'.
    """
    if "@" in service:
        return service
    # Infer provider from router name (e.g. myapp@docker → @docker)
    if "@" in router_name:
        provider = router_name.split("@", 1)[1]
        return f"{service}@{provider}"
    return service


# ──────────────────────────────────────────────────────────
# State inspection
# ──────────────────────────────────────────────────────────

def override_state(settings: Settings, router_name: str) -> OverrideState:
    path = _override_path(settings, router_name)
    if not path.exists():
        return "none"
    try:
        content = yaml.safe_load(path.read_text(encoding="utf-8"))
        routers = content.get("http", {}).get("routers", {})
        for _name, cfg in routers.items():
            if settings.crowdsec_middleware in (cfg.get("middlewares") or []):
                return "on"
        return "off"
    except Exception:
        return "none"


def is_crowdsec_enabled_on_router(middlewares: list[str] | None, crowdsec_ref: str) -> bool:
    return bool(middlewares and crowdsec_ref in middlewares)


# ──────────────────────────────────────────────────────────
# Write / remove overrides
# ──────────────────────────────────────────────────────────

def write_override(
    settings: Settings,
    *,
    router_name: str,
    rule: str,
    service: str,
    entry_points: list[str] | None,
    base_priority: int,
    with_crowdsec: bool,
) -> None:
    """Write a high-priority file-provider router that overrides the Docker one."""
    path = _override_path(settings, router_name)
    svc = _ensure_cross_provider_service(service, router_name)
    prefix = "crowdefik-on" if with_crowdsec else "crowdefik-off"
    override_router_name = f"{prefix}-{_safe_name(router_name)}"
    priority = max(int(base_priority or 0) + 10_000, 100_000)

    router_cfg: dict = {
        "rule": rule,
        "service": svc,
        "priority": priority,
    }
    if entry_points:
        router_cfg["entryPoints"] = entry_points
    if with_crowdsec:
        router_cfg["middlewares"] = [settings.crowdsec_middleware]

    doc = {"http": {"routers": {override_router_name: router_cfg}}}
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def remove_override(settings: Settings, router_name: str) -> None:
    """Remove override file → revert to Docker-label state."""
    path = _override_path(settings, router_name)
    if path.exists():
        path.unlink()


def crowdsec_effective(settings: Settings, router_name: str, label_crowdsec: bool) -> bool:
    """Compute the real effective CrowdSec state for a router."""
    state = override_state(settings, router_name)
    if state == "on":
        return True
    if state == "off":
        return False
    return label_crowdsec
