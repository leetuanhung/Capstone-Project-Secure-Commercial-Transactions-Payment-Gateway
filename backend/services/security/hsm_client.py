# backend/services/security/hsm_client.py
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from backend.config.config import settings

# KEY SOURCE:
# - For local dev: set env var AESGCM_SECRET_BASE64 to a base64-encoded 32-byte key.
# - If not set, a random key will be generated on first import (volatile).
# In production, use a real KMS/HSM to provide the key.
_KEY_ENV = base64.b64encode(os.urandom(32)).decode()

def _load_secret_key() -> bytes:
    s = os.getenv(_KEY_ENV)
    if s:
        try:
            key = base64.b64decode(s)
            if len(key) != 32:
                raise ValueError("AES key must be 32 bytes")
            return key
        except Exception as e:
            raise RuntimeError(f"Invalid { _KEY_ENV } value: {e}")
    return AESGCM.generate_key(bit_length=256)

_SECRET_KEY = _load_secret_key()
_aesgcm = AESGCM(_SECRET_KEY)

def encrypt(plaintext: bytes, associated_data: bytes | None = None) -> bytes:
    iv = os.urandom(12)  # 96-bit recommended for GCM
    ct = _aesgcm.encrypt(iv, plaintext, associated_data)
    blob = iv + ct
    return base64.b64encode(blob)

def decrypt(blob_b64: bytes, associated_data: bytes | None = None) -> bytes:
    raw = base64.b64decode(blob_b64)
    iv = raw[:12]
    ct = raw[12:]
    return _aesgcm.decrypt(iv, ct, associated_data)
