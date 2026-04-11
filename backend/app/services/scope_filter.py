import json
import re
from typing import Any

_HOST = re.compile(r"Host\(\s*`([^`]+)`\s*\)", re.IGNORECASE)


def hosts_from_rules(router_rows: list[dict[str, Any]]) -> set[str]:
    hosts: set[str] = set()
    for r in router_rows:
        rule = r.get("rule")
        if not isinstance(rule, str):
            continue
        for m in _HOST.finditer(rule):
            hosts.add(m.group(1).lower())
    return hosts


def blob_matches_hosts(obj: Any, hosts: set[str]) -> bool:
    if not hosts:
        return False
    blob = json.dumps(obj, default=str).lower()
    return any(h.lower() in blob for h in hosts)
