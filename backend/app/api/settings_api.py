from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import require_superuser
from app.core import crypto
from app.db import get_db
from app.integrations.instance_settings import get_or_create_instance_settings
from app.models import User
from app.schemas import InstanceSettingsOut, InstanceSettingsUpdateIn

router = APIRouter(prefix="/settings", tags=["settings"])


def _row_to_out(row) -> InstanceSettingsOut:
    # Use getattr with defaults so that columns added by migration don't crash
    # the endpoint if the migration hasn't run yet (e.g. container not restarted).
    return InstanceSettingsOut(
        traefik_api_url=row.traefik_api_url,
        traefik_basic_user=row.traefik_basic_user,
        crowdsec_lapi_url=row.crowdsec_lapi_url,
        has_traefik_basic_password=bool(row.traefik_basic_password_enc),
        has_crowdsec_api_key=bool(row.crowdsec_api_key_enc),
        has_abuseipdb_api_key=bool(getattr(row, "abuseipdb_api_key_enc", None)),
        crowdsec_machine_id=getattr(row, "crowdsec_machine_id", None) or None,
        has_crowdsec_machine_password=bool(getattr(row, "crowdsec_machine_pass_enc", None)),
        crowdsec_container_name=getattr(row, "crowdsec_container_name", None) or "crowdsec",
    )


@router.get("", response_model=InstanceSettingsOut)
def get_settings_api(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> InstanceSettingsOut:
    return _row_to_out(get_or_create_instance_settings(db))


@router.put("", response_model=InstanceSettingsOut)
def put_settings_api(
    body: InstanceSettingsUpdateIn,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_superuser)],
) -> InstanceSettingsOut:
    row = get_or_create_instance_settings(db)
    if body.traefik_api_url is not None:
        row.traefik_api_url = body.traefik_api_url
    if body.crowdsec_lapi_url is not None:
        row.crowdsec_lapi_url = body.crowdsec_lapi_url
    if body.traefik_basic_user is not None:
        row.traefik_basic_user = body.traefik_basic_user or None
    if body.traefik_basic_password is not None:
        row.traefik_basic_password_enc = crypto.encrypt_str(body.traefik_basic_password) if body.traefik_basic_password else None
    if body.crowdsec_api_key is not None:
        row.crowdsec_api_key_enc = crypto.encrypt_str(body.crowdsec_api_key) if body.crowdsec_api_key else None
    if body.abuseipdb_api_key is not None:
        row.abuseipdb_api_key_enc = crypto.encrypt_str(body.abuseipdb_api_key) if body.abuseipdb_api_key else None
    try:
        if body.crowdsec_machine_id is not None:
            row.crowdsec_machine_id = body.crowdsec_machine_id or None
        if body.crowdsec_machine_password is not None:
            row.crowdsec_machine_pass_enc = (
                crypto.encrypt_str(body.crowdsec_machine_password) if body.crowdsec_machine_password else None
            )
            from app.integrations.crowdsec_client import invalidate_jwt_cache
            invalidate_jwt_cache(db)
        if body.crowdsec_container_name is not None:
            row.crowdsec_container_name = body.crowdsec_container_name or "crowdsec"
    except Exception:
        pass  # Column not yet migrated — will work after container restart
    db.add(row)
    db.commit()
    db.refresh(row)
    return _row_to_out(row)
