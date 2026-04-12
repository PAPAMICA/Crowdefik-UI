"""
CrowdSec Hub management API — scenarios, collections, and security policies.

Endpoints:
  GET  /api/crowdsec/hub/scenarios           — list installed scenarios + DB stats
  POST /api/crowdsec/hub/scenarios/{name}/install
  DELETE /api/crowdsec/hub/scenarios/{name}
  GET  /api/crowdsec/hub/collections         — list installed collections
  POST /api/crowdsec/hub/collections/{name}/install
  DELETE /api/crowdsec/hub/collections/{name}
  POST /api/crowdsec/hub/update              — cscli hub update
  GET  /api/crowdsec/hub/metrics             — cscli metrics raw output
  GET  /api/crowdsec/global-policy           — get global auto-ban policy
  PUT  /api/crowdsec/global-policy           — update global auto-ban policy
  GET  /api/crowdsec/service-policies        — list all per-service policies
"""
import json
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_superuser
from app.db import get_db
from app.integrations import docker_svc
from app.integrations.instance_settings import get_or_create_instance_settings
from app.models import ServicePolicy, StoredAlert, User

log = logging.getLogger(__name__)

router = APIRouter(prefix="/crowdsec/hub", tags=["hub"])
policy_router = APIRouter(prefix="/crowdsec", tags=["policies"])

GLOBAL_HOST = "__global__"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _container_name(db: Session) -> str:
    return get_or_create_instance_settings(db).crowdsec_container_name or "crowdsec"


def _scenario_alert_counts(db: Session) -> dict[str, int]:
    """Returns a map of scenario name → alert count (all time in DB)."""
    rows = (
        db.query(StoredAlert.scenario, func.count(StoredAlert.id).label("cnt"))
        .filter(StoredAlert.scenario != "")
        .group_by(StoredAlert.scenario)
        .all()
    )
    return {r.scenario: r.cnt for r in rows}


def _normalize_hub_items(raw: Any) -> list[dict[str, Any]]:
    """Robustly flatten cscli JSON output into a list of dicts.

    cscli -o json output varies significantly across CrowdSec versions:
      v1.x old  → dict of dicts:  {"name": {"name": "...", ...}, ...}
      v1.x new  → list of dicts:  [{"name": "...", ...}, ...]
      some builds → dict of lists: {"name": [...fields...], ...}
                    or top-level:  {"collections": [...], "parsers": [...]}

    Strategy:
    - If raw is a list  → keep only dict elements (skip any nested lists).
    - If raw is a dict  → iterate values; keep dicts, unwrap lists-of-dicts.
    - Anything else     → return [].
    """
    items: list[dict[str, Any]] = []

    def _add(v: Any) -> None:
        if isinstance(v, dict):
            items.append(v)
        elif isinstance(v, list):
            for elem in v:
                if isinstance(elem, dict):
                    items.append(elem)

    if isinstance(raw, list):
        for elem in raw:
            _add(elem)
    elif isinstance(raw, dict):
        for v in raw.values():
            _add(v)

    return items


def _policy_to_dict(p: ServicePolicy) -> dict[str, Any]:
    return {
        "host": p.host,
        "min_events_to_display": p.min_events_to_display,
        "auto_ban_enabled": p.auto_ban_enabled,
        "auto_ban_min_score": p.auto_ban_min_score,
        "auto_ban_min_events": p.auto_ban_min_events,
        "auto_ban_window_hours": p.auto_ban_window_hours,
        "auto_ban_duration": p.auto_ban_duration,
        "muted_scenarios": json.loads(p.muted_scenarios) if p.muted_scenarios else [],
        "notes": p.notes,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


# ── Scenarios ──────────────────────────────────────────────────────────────────

@router.get("/scenarios")
def list_scenarios(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """List installed scenarios enriched with alert counts from our DB."""
    name = _container_name(db)
    result = docker_svc.cscli_list_scenarios(name)
    counts = _scenario_alert_counts(db)

    if not result["ok"]:
        return {"ok": False, "error": result.get("error"), "scenarios": []}

    raw = result.get("data") or []
    items = _normalize_hub_items(raw)

    scenarios = []
    for s in items:
        name_full = s.get("name") or s.get("Name") or ""
        scenarios.append({
            "name": name_full,
            "description": s.get("description") or s.get("Description") or "",
            "version": s.get("version") or s.get("Version") or "",
            "status": s.get("status") or s.get("Status") or "installed",
            "local_path": s.get("local_path") or s.get("LocalPath") or "",
            "local_version": s.get("local_version") or s.get("LocalVersion") or "",
            "up_to_date": s.get("up_to_date") or s.get("UpToDate") or False,
            "tainted": s.get("tainted") or s.get("Tainted") or False,
            "alert_count": counts.get(name_full, 0),
        })

    # Sort by alert count descending so most active scenarios are first
    scenarios.sort(key=lambda x: x["alert_count"], reverse=True)
    return {"ok": True, "scenarios": scenarios}


@router.post("/scenarios/{name:path}/install")
def install_scenario(
    name: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    container = _container_name(db)
    result = docker_svc.cscli_install_scenario(name, container)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Install failed"))
    return {"ok": True, "name": name}


@router.delete("/scenarios/{name:path}")
def remove_scenario(
    name: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    container = _container_name(db)
    result = docker_svc.cscli_remove_scenario(name, container)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Remove failed"))
    return {"ok": True, "name": name}


# ── Collections ────────────────────────────────────────────────────────────────

@router.get("/collections")
def list_collections(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    name = _container_name(db)
    result = docker_svc.cscli_list_collections(name)

    if not result["ok"]:
        return {"ok": False, "error": result.get("error"), "collections": []}

    raw = result.get("data") or []
    items = _normalize_hub_items(raw)

    collections = []
    for c in items:
        collections.append({
            "name": c.get("name") or c.get("Name") or "",
            "description": c.get("description") or c.get("Description") or "",
            "version": c.get("version") or c.get("Version") or "",
            "status": c.get("status") or c.get("Status") or "installed",
            "up_to_date": c.get("up_to_date") or c.get("UpToDate") or False,
            "tainted": c.get("tainted") or c.get("Tainted") or False,
        })

    return {"ok": True, "collections": collections}


@router.post("/collections/{name:path}/install")
def install_collection(
    name: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    container = _container_name(db)
    result = docker_svc.cscli_install_collection(name, container)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Install failed"))
    return {"ok": True, "name": name}


@router.delete("/collections/{name:path}")
def remove_collection(
    name: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    container = _container_name(db)
    result = docker_svc.cscli_remove_collection(name, container)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Remove failed"))
    return {"ok": True, "name": name}


# ── Hub operations ─────────────────────────────────────────────────────────────

@router.post("/update")
def hub_update(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    """Refresh the hub index (cscli hub update)."""
    container = _container_name(db)
    result = docker_svc.cscli_hub_update(container)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Hub update failed"))
    return {"ok": True, "output": result.get("output", "")}


@router.get("/metrics")
def hub_metrics(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return raw cscli metrics."""
    container = _container_name(db)
    result = docker_svc.cscli_metrics(container)
    return result


# ── Global & per-service policies ──────────────────────────────────────────────

class PolicyIn(BaseModel):
    min_events_to_display: int = 1
    auto_ban_enabled: bool = False
    auto_ban_min_score: int | None = None
    auto_ban_min_events: int | None = None
    auto_ban_window_hours: int = 24
    auto_ban_duration: str = "24h"
    muted_scenarios: list[str] = []
    notes: str | None = None


@policy_router.get("/global-policy")
def get_global_policy(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return the global default policy (host='__global__')."""
    p = db.query(ServicePolicy).filter(ServicePolicy.host == GLOBAL_HOST).first()
    if not p:
        p = ServicePolicy(
            host=GLOBAL_HOST,
            min_events_to_display=1,
            auto_ban_enabled=False,
            auto_ban_window_hours=24,
            auto_ban_duration="24h",
        )
        db.add(p)
        db.commit()
        db.refresh(p)
    return _policy_to_dict(p)


@policy_router.put("/global-policy")
def update_global_policy(
    body: PolicyIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> dict[str, Any]:
    p = db.query(ServicePolicy).filter(ServicePolicy.host == GLOBAL_HOST).first()
    if not p:
        p = ServicePolicy(host=GLOBAL_HOST)
        db.add(p)
    p.min_events_to_display = body.min_events_to_display
    p.auto_ban_enabled = body.auto_ban_enabled
    p.auto_ban_min_score = body.auto_ban_min_score
    p.auto_ban_min_events = body.auto_ban_min_events
    p.auto_ban_window_hours = body.auto_ban_window_hours
    p.auto_ban_duration = body.auto_ban_duration
    p.muted_scenarios = json.dumps(body.muted_scenarios)
    p.notes = body.notes
    db.commit()
    db.refresh(p)
    return _policy_to_dict(p)


@policy_router.get("/service-policies")
def list_service_policies(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return all per-service policies (excluding the global one)."""
    policies = (
        db.query(ServicePolicy)
        .filter(ServicePolicy.host != GLOBAL_HOST)
        .order_by(ServicePolicy.host)
        .all()
    )
    # Enrich with alert count per service
    host_counts = dict(
        db.query(StoredAlert.target_host, func.count(StoredAlert.id).label("cnt"))
        .filter(StoredAlert.target_host.isnot(None))
        .group_by(StoredAlert.target_host)
        .all()
    )
    return {
        "policies": [
            {**_policy_to_dict(p), "alert_count": host_counts.get(p.host, 0)}
            for p in policies
        ]
    }
