"""Tests for HSM client.

We mock HSMClient methods using pytest-mock to keep the unit test stable across
environments. For true integration testing against AWS KMS use moto or a real
KMS in separate integration tests.
"""

from backend.services.payment_service.security.hsm_client import HSMClient


def test_hsm_client_encrypt_decrypt_mock(mocker):
    """Unit test that mocks HSMClient.encrypt_data/decrypt_data."""
    # Prevent network calls during init by disabling auto_init in tests
    h = HSMClient(region_name="us-east-1", auto_init=False)
    plaintext = "4111111111111111"

    fake_ciphertext = "ZmFrZUNpcGhlcnRleHQ="  # base64 for 'fakeCiphertext'

    # Patch instance methods
    mocker.patch.object(HSMClient, "encrypt_data", return_value=fake_ciphertext)
    mocker.patch.object(HSMClient, "decrypt_data", return_value=plaintext)

    ct = h.encrypt_data(plaintext, key_id="test-key")
    assert ct == fake_ciphertext

    dec = h.decrypt_data(ct, key_id="test-key")
    assert dec == plaintext