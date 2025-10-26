import logging
from passlib.context import CryptContext
from fastapi import HTTPException

# Use bcrypt_sha256 so passlib pre-hashes long passwords with SHA-256 and avoids bcrypt's 72-byte limit
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

def validate_password(password: str) -> None:
    if len(password) < 8:
        raise ValueError("Mật khẩu phải có ít nhất 8 ký tự")
    if not any(c.isupper() for c in password):
        raise ValueError("Mật khẩu phải có ít nhất 1 chữ in hoa")
    if not any(c.islower() for c in password):
        raise ValueError("Mật khẩu phải có ít nhất 1 chữ thường")
    if not any(c.isdigit() for c in password):
        raise ValueError("Mật khẩu phải có ít nhất 1 số")

def hash_password(password: str) -> str:
    try:
        validate_password(password)
        # Using bcrypt_sha256 avoids the 72-byte bcrypt limit. Log if password is unusually long.
        pw_bytes_len = len(password.encode("utf-8"))
        return pwd_context.hash(password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


def verify(plain_password: str, hashed_password: str) -> bool:
    """Kiểm tra mật khẩu người dùng nhập có khớp hash không."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logging.exception("Error verifying password:")
        return False
# keep original name for compatibility
hash = hash_password