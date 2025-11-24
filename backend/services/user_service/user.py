import base64
import hashlib
import json
import os
import string
from typing import Optional

from fastapi import APIRouter, Form, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sqlalchemy.orm import Session

from backend.database.database import get_db, SessionLocal
from backend.models.models import User
from backend.schemas import user
from backend.utils import crypto
from backend.oauth2 import oauth2
from backend.services.payment_service.security.encryption import AESEncryption
import logging

from backend.utils.logger import(
    get_security_logger,
    log_security_event,
    log_audit_trail
)

logger = get_security_logger()

router = APIRouter(prefix="/auth", tags=["Authentication"])

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend" / "templates"))


USER_AES_KEY_ENV = "USER_AES_KEY"
LEGACY_AES_KEY_ENV = "Key_AES"
_USER_AES_KEY_CACHE: Optional[bytes] = None


def _get_user_encryption_key() -> bytes:
    global _USER_AES_KEY_CACHE
    if _USER_AES_KEY_CACHE is not None:
        return _USER_AES_KEY_CACHE

    key_b64 = os.getenv(USER_AES_KEY_ENV) or os.getenv(LEGACY_AES_KEY_ENV)
    if not key_b64:
        raise RuntimeError(
            "USER_AES_KEY environment variable is required to encrypt user data."
        )

    try:
        key = base64.b64decode(key_b64)
    except Exception as exc:  # pragma: no cover - defensive guard
        raise RuntimeError("USER_AES_KEY must be base64 encoded.") from exc

    if len(key) != 32:
        raise RuntimeError("USER_AES_KEY must decode to 32 bytes (AES-256 key length).")

    _USER_AES_KEY_CACHE = key
    return key


def _normalize(value: str) -> str:
    return value.strip()


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.lower().encode("utf-8")).hexdigest()


def _name_aad(name_hash: str) -> bytes:
    return f"user:name:{name_hash}".encode("utf-8")


def _email_aad(email_hash: str) -> bytes:
    return f"user:email:{email_hash}".encode("utf-8")


def _normalize_phone(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def _phone_aad(phone_hash: str) -> bytes:
    return f"user:phone:{phone_hash}".encode("utf-8")


def _looks_like_hash(value: str) -> bool:
    return len(value) == 64 and all(c in string.hexdigits for c in value)


def _encrypt_value(value: str, aad: bytes) -> str:
    encrypted = AESEncryption.encrypt_aes_gcm(value, _get_user_encryption_key(), aad)
    return json.dumps(encrypted)


def _decrypt_value(blob: Optional[str], aad: bytes) -> Optional[str]:
    if not blob:
        return None
    try:
        payload = json.loads(blob)
        return AESEncryption.decrypt_aes_gcm(payload, _get_user_encryption_key(), aad)
    except Exception:
        return None


def _get_user_by_identifier(identifier: str, db: Session) -> Optional[User]:
    normalized = _normalize(identifier)

    if "@" in normalized:
        email_normalized = normalized.lower()
        email_hash = _hash_value(email_normalized)
        user = db.query(User).filter(User.email == email_hash).first()
        if user:
            return user
        legacy = db.query(User).filter(User.email == email_normalized).first()
        if legacy:
            _upgrade_legacy_user_record(legacy, db)
            db.commit()
            db.refresh(legacy)
            return legacy
        return None

    phone_digits = _normalize_phone(normalized)
    if phone_digits and 8 <= len(phone_digits) <= 15:
        phone_hash = _hash_value(phone_digits)
        user = db.query(User).filter(User.phone == phone_hash).first()
        if user:
            return user
        legacy = db.query(User).filter(User.phone == phone_digits).first()
        if legacy:
            _upgrade_legacy_user_record(legacy, db)
            db.commit()
            db.refresh(legacy)
            return legacy
        return None

    name_hash = _hash_value(normalized)
    user = db.query(User).filter(User.name == name_hash).first()
    if user:
        return user
    legacy = db.query(User).filter(User.name == normalized).first()
    if legacy:
        _upgrade_legacy_user_record(legacy, db)
        db.commit()
        db.refresh(legacy)
        return legacy
    return None


def _upgrade_legacy_user_record(user_obj: User, session: Session) -> None:
    """Upgrade legacy records that still store plaintext user attributes."""
    updated = False

    if user_obj.name_encrypted is None and user_obj.name:
        name_plain = user_obj.name
        if not _looks_like_hash(name_plain):
            normalized_name = _normalize(name_plain)
            name_hash = _hash_value(normalized_name)
            user_obj.name = name_hash
            user_obj.name_encrypted = _encrypt_value(normalized_name, _name_aad(name_hash))
            updated = True

    if user_obj.email_encrypted is None and user_obj.email:
        email_plain = user_obj.email
        if not _looks_like_hash(email_plain):
            normalized_email = _normalize(email_plain).lower()
            email_hash = _hash_value(normalized_email)
            user_obj.email = email_hash
            user_obj.email_encrypted = _encrypt_value(normalized_email, _email_aad(email_hash))
            updated = True

    if user_obj.phone_encrypted is None and user_obj.phone:
        phone_plain = user_obj.phone
        if not _looks_like_hash(phone_plain):
            normalized_phone = _normalize_phone(phone_plain)
            if normalized_phone:
                phone_hash = _hash_value(normalized_phone)
                user_obj.phone = phone_hash
                user_obj.phone_encrypted = _encrypt_value(normalized_phone, _phone_aad(phone_hash))
                updated = True

    if updated:
        session.add(user_obj)


def ensure_user_security_setup() -> None:
    """Run once at startup to migrate legacy user rows to encrypted format."""
    session = SessionLocal()
    try:
        legacy_users = (
            session.query(User)
            .filter(
                (User.name_encrypted == None)  # noqa: E711
                | (User.email_encrypted == None)  # noqa: E711
                | ((User.phone != None) & (User.phone_encrypted == None))  # noqa: E711
            )
            .all()
        )
        for legacy in legacy_users:
            _upgrade_legacy_user_record(legacy, session)
        if legacy_users:
            session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@router.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        logger.info(
            'Login attempt',
            extra = {'username': username, 'ip': request.client.host}
        )
        user_db = _get_user_by_identifier(username, db)
    except RuntimeError as exc:
        db.rollback()
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": str(exc)
        })

    if not user_db:
        
        log_security_event(
            event_type = 'login_failed',
            severity = 'warning',
            user_id = None,
            ip_address=request.client.host,
            details={'username': username, 'reason': 'user_not_found'}
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Thông tin đăng nhập không đúng"
        })

    is_valid = crypto.verify(password, user_db.password)

    if not is_valid:
        
        log_security_event(
            event_type = 'login_failed',
            severity='warning',
            user_id=user_db.id,
            ip_address=request.client.host,
            details={'reason': 'invalid_password'}
        )
        
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Email hoặc mật khẩu không đúng"
        })

    display_name = _decrypt_value(user_db.name_encrypted, _name_aad(user_db.name)) or _normalize(username)
    access_token = oauth2.create_access_token(data={"user_id": user_db.id})

    log_security_event(
        event_type='login_success',
        severity='info',
        user_id = user_db.id,
        ip_address=request.client.host,
        details={'username': username}
    )
    logger.info(f"User {user_db.id} logged in successfully")

    return templates.TemplateResponse("welcome.html", {
        "request": request,
        "username": display_name,
        "access_token": access_token,
        "user_id": user_db.id
    })

@router.get("/register", response_class=HTMLResponse)
async def register_get(request: Request):
    return templates.TemplateResponse("register.html", {
        "request": request, 
        "error": None
    })

@router.post("/register", response_class=HTMLResponse)
async def register_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    
    normalized_name = _normalize(name)
    normalized_email = _normalize(email).lower()
    normalized_phone = _normalize_phone(phone)
    if not normalized_phone:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Số điện thoại không hợp lệ"
        })
    if len(normalized_phone) < 8 or len(normalized_phone) > 15:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Số điện thoại phải có từ 8 đến 15 chữ số"
        })
    name_hash = _hash_value(normalized_name)
    email_hash = _hash_value(normalized_email)
    phone_hash = _hash_value(normalized_phone)

    exists_email = db.query(User).filter(User.email == email_hash).first()
    if not exists_email:
        legacy_email = db.query(User).filter(User.email == normalized_email).first()
        if legacy_email:
            try:
                _upgrade_legacy_user_record(legacy_email, db)
                db.commit()
                exists_email = legacy_email
            except RuntimeError as exc:
                db.rollback()
                return templates.TemplateResponse("register.html", {
                    "request": request,
                    "error": str(exc)
                })
    if exists_email:
        print("ERROR: Email already exists")
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Email đã tồn tại"
        })

    exists_phone = db.query(User).filter(User.phone == phone_hash).first()
    if not exists_phone:
        legacy_phone = db.query(User).filter(User.phone == normalized_phone).first()
        if legacy_phone:
            try:
                _upgrade_legacy_user_record(legacy_phone, db)
                db.commit()
                exists_phone = legacy_phone
            except RuntimeError as exc:
                db.rollback()
                return templates.TemplateResponse("register.html", {
                    "request": request,
                    "error": str(exc)
                })
    if exists_phone:
        print("ERROR: Phone already exists")
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Số điện thoại đã tồn tại"
        })
    
    if password != confirm_password:
        print("ERROR: Passwords don't match")
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Mật khẩu không khớp"
        })
    
    if len(password) < 6:
        print("ERROR: Password too short")
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Mật khẩu phải có ít nhất 6 ký tự"
        })
    
    try:
        try:
            name_encrypted = _encrypt_value(normalized_name, _name_aad(name_hash))
            email_encrypted = _encrypt_value(normalized_email, _email_aad(email_hash))
            phone_encrypted = _encrypt_value(normalized_phone, _phone_aad(phone_hash))
        except RuntimeError as exc:
            return templates.TemplateResponse("register.html", {
                "request": request,
                "error": str(exc)
            })
        hashed_pass = crypto.hash(password)
        new_user = User(
            name=name_hash,
            email=email_hash,
            password=hashed_pass,
            name_encrypted=name_encrypted,
            email_encrypted=email_encrypted,
            phone=phone_hash,
            phone_encrypted=phone_encrypted
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return RedirectResponse(
            url="/", 
            status_code=303
        )
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        db.rollback()
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": f"Lỗi server: {str(e)}"
        })