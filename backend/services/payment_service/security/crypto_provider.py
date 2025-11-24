"""
Backend Ephemeral Key Provider for E2E Encryption
===================================================
Mục đích: Cung cấp ephemeral RSA public key cho frontend để mã hóa metadata

Flow:
    1. Frontend GET /api/get_encryption_key
    2. Backend tạo RSA key pair (ephemeral, rotate mỗi 1h)
    3. Trả về public key (JWK format)
    4. Frontend mã hóa metadata với public key
    5. Backend giải mã với private key

Security:
    - Private key lưu trong memory (không persist)
    - Rotate key mỗi 1 giờ hoặc mỗi N requests
    - Rate limit endpoint này
"""

from fastapi import APIRouter, HTTPException
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import json
import base64
import time
from typing import Dict, Tuple

router = APIRouter()

# Global ephemeral key cache (in-memory)
_ephemeral_key_cache = {
    "private_key": None,
    "public_key_jwk": None,
    "created_at": 0,
    "rotation_interval": 3600  # 1 hour
}


def _generate_ephemeral_keypair() -> Tuple[rsa.RSAPrivateKey, Dict]:
    """
    Tạo RSA key pair mới (ephemeral)
    
    Returns:
        Tuple of (private_key, public_key_jwk)
    """
    # Generate RSA-2048 (hoặc 4096 nếu muốn mạnh hơn, nhưng chậm hơn)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    # Export public key to JWK (JSON Web Key) format for Web Crypto API
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Convert PEM to JWK manually (simplified)
    # Production: use python-jose or jwcrypto library
    # For now, return base64 PEM and let frontend parse
    public_key_b64 = base64.b64encode(public_pem).decode()
    
    public_key_jwk = {
        "kty": "RSA",
        "alg": "RSA-OAEP-256",
        "use": "enc",
        "key": public_key_b64  # Base64 PEM (frontend sẽ import)
    }
    
    return private_key, public_key_jwk


def get_current_ephemeral_key() -> Tuple[rsa.RSAPrivateKey, Dict]:
    """
    Lấy hoặc tạo mới ephemeral key pair
    Key sẽ tự động rotate sau rotation_interval seconds
    
    Returns:
        Tuple of (private_key, public_key_jwk)
    """
    current_time = time.time()
    
    # Check if need to rotate
    if (_ephemeral_key_cache["private_key"] is None or 
        current_time - _ephemeral_key_cache["created_at"] > _ephemeral_key_cache["rotation_interval"]):
        
        print("[Security] Rotating ephemeral encryption key...")
        private_key, public_key_jwk = _generate_ephemeral_keypair()
        
        _ephemeral_key_cache["private_key"] = private_key
        _ephemeral_key_cache["public_key_jwk"] = public_key_jwk
        _ephemeral_key_cache["created_at"] = current_time
    
    return _ephemeral_key_cache["private_key"], _ephemeral_key_cache["public_key_jwk"]


@router.get("/get_encryption_key")
async def get_encryption_key():
    """
    API endpoint để frontend lấy ephemeral public key
    
    Response:
        {
            "public_key": {...},  # JWK format
            "key_id": "...",      # Key rotation tracking
            "expires_in": 3600    # Seconds until rotation
        }
    """
    try:
        private_key, public_key_jwk = get_current_ephemeral_key()
        
        # Calculate remaining lifetime
        elapsed = time.time() - _ephemeral_key_cache["created_at"]
        expires_in = max(0, _ephemeral_key_cache["rotation_interval"] - elapsed)
        
        return {
            "public_key": public_key_jwk,
            "key_id": f"ephemeral-{int(_ephemeral_key_cache['created_at'])}",
            "expires_in": int(expires_in)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key generation failed: {str(e)}")


def decrypt_metadata(encrypted_data: str, encrypted_key: str, iv: str) -> str:
    """
    Giải mã metadata được mã hóa bởi frontend
    
    Args:
        encrypted_data: Base64-encoded AES-GCM ciphertext
        encrypted_key: Base64-encoded RSA-encrypted AES key
        iv: Base64-encoded initialization vector
    
    Returns:
        Decrypted plaintext
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    
    private_key, _ = get_current_ephemeral_key()
    
    # 1. Decrypt AES key using RSA private key
    encrypted_key_bytes = base64.b64decode(encrypted_key)
    aes_key = private_key.decrypt(
        encrypted_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 2. Decrypt data using AES-GCM
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    iv_bytes = base64.b64decode(iv)
    
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv_bytes, tag=encrypted_data_bytes[-16:]),  # Last 16 bytes = auth tag
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(encrypted_data_bytes[:-16]) + decryptor.finalize()
    
    return plaintext.decode('utf-8')


# Example usage in payment route:
# from .crypto_provider import decrypt_metadata
# 
# @router.post("/create_payment")
# async def create_payment(encrypted_cardholder_name: str, ...):
#     cardholder_name = decrypt_metadata(
#         encrypted_cardholder_name["encryptedData"],
#         encrypted_cardholder_name["encryptedKey"],
#         encrypted_cardholder_name["iv"]
#     )
#     ...
