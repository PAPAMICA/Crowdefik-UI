import base64
import hashlib

from cryptography.fernet import Fernet

from app.settings import get_settings


def _fernet() -> Fernet:
    raw = hashlib.sha256(get_settings().app_secret.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt_str(plain: str) -> str:
    return _fernet().encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_str(token: str) -> str:
    return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
