import os
from backend.services.payment_service.security.encryption import FieldEncryption


def test_encrypt_decrypt_roundtrip():
    fe = FieldEncryption()  # uses generated key if env not set
    plaintext = "hello secret"
    ctx = {"id": "test-1"}
    encrypted = fe.encrypt_field(plaintext, context=ctx)
    assert isinstance(encrypted, str) and encrypted
    decrypted = fe.decrypt_field(encrypted, context=ctx)
    assert decrypted == plaintext


def test_context_mismatch_raises():
    fe = FieldEncryption()
    encrypted = fe.encrypt_field("data", context={"a": 1})
    try:
        fe.decrypt_field(encrypted, context={"a": 2})
        assert False, "Expected context mismatch to raise ValueError"
    except ValueError:
        # expected
        pass
# tests/test_encryption.py
import os
from backend.services.payment_service.security.encryption import FieldEncryption

def test_encrypt_decrypt_roundtrip():
    fe = FieldEncryption()  # uses generated key if env not set
    plaintext = "hello secret"
    ctxt = {"id": "test-1"}
    encrypted = fe.encrypt_field(plaintext, context=ctxt)
    assert isinstance(encrypted, str) and encrypted
    decrypted = fe.decrypt_field(encrypted, context=ctxt)
    assert decrypted == plaintext

def test_context_mismatch_raises():
    fe = FieldEncryption()
    encrypted = fe.encrypt_field("data", context={"a": 1})
    try:
        fe.decrypt_field(encrypted, context={"a": 2})
        # If no exception, fail
        assert False, "Expected context mismatch"
    except ValueError:
        pass