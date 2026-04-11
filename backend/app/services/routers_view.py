from collections import defaultdict
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


def _entry_points(r: dict[str, Any]) -> list[str]:
    return [ep.lower() for ep in (r.get("entry_points") or r.get("entryPoints") or [])]


def _dedup_prefer_https(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    When several routers share the exact same rule (e.g. one on 'http' that
    redirects and one on 'https' that serves the real content), keep only the
    HTTPS router.  If a rule has no HTTPS router at all, keep whatever exists.

    Also removes routers that only listen on internal/metrics entrypoints.
    """
    # Group by normalised rule
    by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_rule[str(row.get("rule") or "")].append(row)

    result: list[dict[str, Any]] = []
    for group in by_rule.values():
        https_rows = [r for r in group if "https" in _entry_points(r)]
        if https_rows:
            result.extend(https_rows)
        else:
            # No HTTPS alternative — keep non-metrics-only routers
            non_internal = [
                r for r in group
                if not all(ep in ("metrics", "traefik") for ep in _entry_points(r))
            ]
            result.extend(non_internal or group)

    return result


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

    return _dedup_prefer_https(rows)


def filter_rows_for_user(
    rows: list[dict[str, Any]], *, is_superuser: bool, allowed_routers: set[str],
) -> list[dict[str, Any]]:
    if is_superuser:
        return rows
    return [r for r in rows if r["name"] in allowed_routers]
