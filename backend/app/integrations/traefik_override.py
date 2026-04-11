import re
from pathlib import Path

import yaml

from app.settings import Settings


def _safe_router_filename(router_name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", router_name.replace("@", "-at-"))
    return s.strip("-")[:200] or "router"


def override_dir(settings: Settings) -> Path:
    d = settings.traefik_custom_dir / settings.traefik_override_subdir
    d.mkdir(parents=True, exist_ok=True)
    return d


def override_path(settings: Settings, router_name: str) -> Path:
    return override_dir(settings) / f"{_safe_router_filename(router_name)}.yml"


def is_crowdsec_enabled_on_router(middlewares: list[str] | None, crowdsec_ref: str) -> bool:
    if not middlewares:
        return False
    return crowdsec_ref in middlewares


def write_bypass_router(
    settings: Settings,
    *,
    router_name: str,
    rule: str,
    service: str,
    entry_points: list[str] | None,
    base_priority: int,
) -> None:
    """High-priority router without CrowdSec middleware; shadows the original router."""
    path = override_path(settings, router_name)
    override_router_name = f"crowdefik-off-{_safe_router_filename(router_name)}"
    priority = max(int(base_priority or 0) + 10_000, 100_000)
    doc = {
        "http": {
            "routers": {
                override_router_name: {
                    "rule": rule,
                    "service": service,
                    "priority": priority,
                }
            }
        }
    }
    if entry_points:
        doc["http"]["routers"][override_router_name]["entryPoints"] = entry_points
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def remove_bypass_router(settings: Settings, router_name: str) -> None:
    path = override_path(settings, router_name)
    if path.exists():
        path.unlink()


def crowdsec_bypass_active(settings: Settings, router_name: str) -> bool:
    return override_path(settings, router_name).exists()
