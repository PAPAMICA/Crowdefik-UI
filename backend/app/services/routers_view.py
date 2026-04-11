from typing import Any

from app.integrations.traefik_override import crowdsec_effective as compute_effective
from app.integrations.traefik_override import is_crowdsec_enabled_on_router, override_state
from app.settings import get_settings


def _is_public_http_router(r: dict[str, Any]) -> bool:
    name = r.get("name") or ""
    if not name.endswith("@docker"):
        return False
    if r.get("status") != "enabled":
        return False
    if name.endswith("@internal"):
        return False
    return True


def build_router_rows(routers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    settings = get_settings()
    crowdsec_ref = settings.crowdsec_middleware
    rows: list[dict[str, Any]] = []
    for r in routers:
        if not _is_public_http_router(r):
            continue
        name = r["name"]
        middlewares = r.get("middlewares") or []
        label_has = is_crowdsec_enabled_on_router(middlewares, crowdsec_ref)
        ov_state = override_state(settings, name)
        effective = compute_effective(settings, name, label_has)
        rows.append(
            {
                "name": name,
                "rule": r.get("rule"),
                "service": r.get("service"),
                "entry_points": r.get("entryPoints") or [],
                "middlewares": middlewares,
                "priority": r.get("priority") or 0,
                "label_crowdsec": label_has,
                "override_state": ov_state,   # "on" | "off" | "none"
                "crowdsec_effective": effective,
            }
        )
    return rows


def filter_rows_for_user(rows: list[dict[str, Any]], *, is_superuser: bool, allowed_routers: set[str]) -> list[dict[str, Any]]:
    if is_superuser:
        return rows
    return [r for r in rows if r["name"] in allowed_routers]
