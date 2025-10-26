from backend.services.security.hsm_client import encrypt, decrypt

def encrypt_field(value: str, aad: str | None = None) -> str:
    aad_b = aad.encode() if aad else None
    blob = encrypt(value.encode(), associated_data=aad_b)
    return blob.decode()

def decrypt_field(blob_b64_str: str, aad: str | None = None) -> str:
    aad_b = aad.encode() if aad else None
    pt = decrypt(blob_b64_str.encode(), associated_data=aad_b)
    return pt.decode()
