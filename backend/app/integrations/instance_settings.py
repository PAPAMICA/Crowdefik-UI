from sqlalchemy.orm import Session

from app.core import crypto
from app.models import InstanceSettings


def get_or_create_instance_settings(db: Session) -> InstanceSettings:
    row = db.query(InstanceSettings).filter(InstanceSettings.id == 1).one_or_none()
    if row is None:
        row = InstanceSettings(id=1)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def traefik_basic_password_plain(db: Session) -> str | None:
    row = get_or_create_instance_settings(db)
    if not row.traefik_basic_password_enc:
        return None
    return crypto.decrypt_str(row.traefik_basic_password_enc)


def crowdsec_api_key_plain(db: Session) -> str | None:
    row = get_or_create_instance_settings(db)
    if not row.crowdsec_api_key_enc:
        return None
    return crypto.decrypt_str(row.crowdsec_api_key_enc)
