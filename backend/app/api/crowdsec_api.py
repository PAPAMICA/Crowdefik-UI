import json as _json
import math
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import allowed_router_names, get_current_user, require_superuser
from app.core import cache as cache_mod
from app.core.audit import log_action
from app.db import get_db
from app.integrations import crowdsec_client, docker_svc, traefik_client
from app.integrations.instance_settings import (
    crowdsec_api_key_plain,
    crowdsec_machine_password_plain,
    get_or_create_instance_settings,
)
from app.models import User
from app.services.routers_view import build_router_rows, filter_rows_for_user
from app.services.scope_filter import blob_matches_hosts, hosts_from_rules
from app.settings import get_settings


class BanIn(BaseModel):
    ip: str
    duration: str = "24h"
    reason: str = "manual"
    type: str = "ban"


class BouncerAddIn(BaseModel):
    name: str


class MachineAddIn(BaseModel):
    machine_id: str
    password: str

router = APIRouter(prefix="/crowdsec", tags=["crowdsec"])


def _visible_hosts(db: Session, user: User) -> set[str] | None:
    if user.is_superuser:
        return None
    allowed = allowed_router_names(db, user)

    def factory():
        return traefik_client.fetch_routers_sync(db)

    raw = cache_mod.get_cached("traefik:routers", factory)
    rows = build_router_rows(raw)
    visible = filter_rows_for_user(rows, is_superuser=False, allowed_routers=allowed)
    return hosts_from_rules(visible)


@router.get("/decisions")
def list_decisions(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    limit: int = 200,
) -> list[dict[str, Any]]:
    s = get_settings()

    def factory():
        return crowdsec_client.fetch_decisions_sync(db)

    decisions = cache_mod.get_cached("crowdsec:decisions", factory, ttl_seconds=s.crowdsec_cache_ttl_seconds)
    hosts = _visible_hosts(db, user)
    raw = decisions[:limit] if hosts is None else [d for d in decisions if blob_matches_hosts(d, hosts)][:limit]
    return _enrich_decisions_with_service(db, raw)


def _enrich_decisions_with_service(db: Session, decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add _target_host to each decision by looking up the most common alert target for that IP."""
    from sqlalchemy import func
    from app.models import StoredAlert
    ips = list({str(d.get("value") or d.get("ip") or "") for d in decisions if d.get("value") or d.get("ip")})
    if not ips:
        return decisions
    # For each IP, find the most common target_host in stored alerts
    rows = (
        db.query(StoredAlert.source_ip, StoredAlert.target_host, func.count(StoredAlert.id).label("n"))
        .filter(StoredAlert.source_ip.in_(ips), StoredAlert.target_host.isnot(None))
        .group_by(StoredAlert.source_ip, StoredAlert.target_host)
        .all()
    )
    # Pick the top host per IP
    from collections import defaultdict
    ip_hosts: dict[str, dict[str, int]] = defaultdict(dict)
    for ip, host, n in rows:
        ip_hosts[ip][host] = n
    top_host = {ip: max(hosts, key=hosts.__getitem__) for ip, hosts in ip_hosts.items()}
    for d in decisions:
        ip = str(d.get("value") or d.get("ip") or "")
        if ip in top_host:
            d["_target_host"] = top_host[ip]
    return decisions


@router.post("/decisions")
def ban_ip(
    body: BanIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Manually ban an IP via CrowdSec LAPI (requires watcher credentials + superuser)."""
    if not user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superuser required")
    result = crowdsec_client.add_decision(db, ip=body.ip, duration=body.duration, reason=body.reason, decision_type=body.type)
    if not result.get("ok"):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=result.get("error", "Unknown error"))
    cache_mod.invalidate_prefix("crowdsec:")
    log_action(db, user, "ban", target=body.ip, detail=f"duration={body.duration} reason={body.reason}")
    return result


@router.delete("/decisions/{decision_id}")
def unban_decision(
    decision_id: int,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Delete a CrowdSec decision (unban an IP)."""
    if not user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superuser required")
    result = crowdsec_client.delete_decision(db, decision_id)
    if not result.get("ok"):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=result.get("error", "Unknown error"))
    cache_mod.invalidate_prefix("crowdsec:")
    log_action(db, user, "unban", target=str(decision_id))
    return result


def _container_name(db: Session) -> str:
    s = get_or_create_instance_settings(db)
    return getattr(s, "crowdsec_container_name", None) or "crowdsec"


@router.get("/bouncers")
def list_bouncers(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    result = docker_svc.cscli_list_bouncers(_container_name(db))
    if not result.get("ok"):
        return {"ok": False, "error": result.get("error"), "data": []}
    data = result.get("data") or []
    if isinstance(data, dict) and "items" in data:
        data = data["items"]
    return {"ok": True, "data": data if isinstance(data, list) else []}


@router.post("/bouncers")
def add_bouncer(
    body: BouncerAddIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    result = docker_svc.cscli_add_bouncer(body.name, _container_name(db))
    if result.get("ok"):
        log_action(db, user, "add_bouncer", target=body.name)
    return result


@router.delete("/bouncers/{name}")
def delete_bouncer(
    name: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    result = docker_svc.cscli_delete_bouncer(name, _container_name(db))
    if result.get("ok"):
        log_action(db, user, "delete_bouncer", target=name)
    return result


@router.get("/machines")
def list_machines(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    result = docker_svc.cscli_list_machines(_container_name(db))
    if not result.get("ok"):
        return {"ok": False, "error": result.get("error"), "data": []}
    data = result.get("data") or []
    if isinstance(data, dict) and "items" in data:
        data = data["items"]
    return {"ok": True, "data": data if isinstance(data, list) else []}


@router.post("/machines")
def add_machine(
    body: MachineAddIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    result = docker_svc.cscli_add_machine(body.machine_id, body.password, _container_name(db))
    if result.get("ok"):
        log_action(db, user, "add_machine", target=body.machine_id)
    return result


@router.delete("/machines/{machine_id}")
def delete_machine(
    machine_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    result = docker_svc.cscli_delete_machine(machine_id, _container_name(db))
    if result.get("ok"):
        log_action(db, user, "delete_machine", target=machine_id)
    return result


@router.post("/machines/{machine_id}/validate")
def validate_machine(
    machine_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    result = docker_svc.cscli_validate_machine(machine_id, _container_name(db))
    if result.get("ok"):
        log_action(db, user, "validate_machine", target=machine_id)
    return result


@router.get("/metrics")
def get_crowdsec_metrics(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    """Fetch all CrowdSec metrics via `cscli metrics -o json`."""
    return docker_svc.cscli_metrics(_container_name(db))


@router.get("/status")
def crowdsec_status(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return connectivity / auth status for CrowdSec (no external calls, just checks configuration)."""
    s = get_or_create_instance_settings(db)

    bouncer_ok = bool(crowdsec_api_key_plain(db))

    machine_id = getattr(s, "crowdsec_machine_id", None) or None
    machine_pass = crowdsec_machine_password_plain(db) if machine_id else None
    watcher_configured = bool(machine_id and machine_pass)

    return {
        "bouncer_configured": bouncer_ok,
        "watcher_configured": watcher_configured,
        "machine_id": machine_id,
        "lapi_url": s.crowdsec_lapi_url,
    }


@router.get("/alerts/filters")
def list_alert_filters(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, list[str]]:
    """Return distinct scenarios and target hosts for filter dropdowns."""
    from app.models import StoredAlert
    from sqlalchemy import distinct as sql_distinct

    hosts = _visible_hosts(db, user)
    q_sc = db.query(sql_distinct(StoredAlert.scenario)).filter(StoredAlert.scenario != "")
    q_h = db.query(sql_distinct(StoredAlert.target_host)).filter(StoredAlert.target_host.isnot(None))
    if hosts is not None:
        q_sc = q_sc.filter(StoredAlert.target_host.in_(hosts))
        q_h = q_h.filter(StoredAlert.target_host.in_(hosts))

    return {
        "scenarios": sorted([r[0].replace("crowdsecurity/", "") for r in q_sc.all() if r[0]]),
        "hosts": sorted([r[0] for r in q_h.all() if r[0]]),
    }


@router.get("/alerts")
def list_alerts(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    page: int = 1,
    limit: int = 25,
    scenario: str | None = None,
    host: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """Serve alerts from the local DB with server-side pagination and filtering.

    No arbitrary 2000-item cap — returns the full 7-day rolling history.
    """
    from app.models import StoredAlert
    from app.services.sync_service import _extract_target_host
    from sqlalchemy import or_

    hosts = _visible_hosts(db, user)
    q = db.query(StoredAlert).order_by(StoredAlert.start_at.desc())

    if hosts is not None:
        q = q.filter(StoredAlert.target_host.in_(hosts))
    if scenario:
        q = q.filter(StoredAlert.scenario.ilike(f"%{scenario}%"))
    if host:
        q = q.filter(StoredAlert.target_host == host)
    if search:
        s = f"%{search}%"
        q = q.filter(
            or_(
                StoredAlert.source_ip.ilike(s),
                StoredAlert.scenario.ilike(s),
                StoredAlert.target_host.ilike(s),
            )
        )

    total = q.count()
    limit = max(1, min(limit, 500))
    rows = q.offset((page - 1) * limit).limit(limit).all()

    alerts: list[dict[str, Any]] = []
    for row in rows:
        try:
            a: dict[str, Any] = _json.loads(row.raw_json)
        except Exception:
            a = {"id": row.id, "scenario": row.scenario, "source": {"ip": row.source_ip}}

        a["_target_host"] = row.target_host
        if not a["_target_host"]:
            live = _extract_target_host(a)
            if live:
                a["_target_host"] = live
        alerts.append(a)

    return {
        "total": total,
        "page": page,
        "pages": math.ceil(total / limit) if total else 0,
        "alerts": alerts,
    }
