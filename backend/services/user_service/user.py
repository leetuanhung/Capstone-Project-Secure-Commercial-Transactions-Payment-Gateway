import base64
import hashlib
import json
import os
import string
import time
from typing import Optional

from fastapi import APIRouter, Form, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sqlalchemy.orm import Session

from backend.database.database import get_db, SessionLocal
from backend.models.models import User
from backend.schemas import user
from backend.utils import crypto
from backend.utils import csrf
from backend.oauth2 import oauth2
from backend.services.payment_service.security.encryption import AESEncryption
from backend.services.payment_service.otp_service import OTPService
import logging

from backend.utils.logger import(
    get_security_logger,
    log_security_event,
    log_audit_trail
)

logger = get_security_logger()

# Router prefix is intentionally empty.
# The app mounts this router under both `/auth` and `/user_service` in `backend/main.py`.
router = APIRouter(tags=["Authentication"])

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend" / "templates"))

# Khởi tạo OTP service
otp_service = OTPService()


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
    csrf_token: Optional[str] = Form(None),
    username: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    # Defensive: some browsers/proxies can trigger a POST without a body
    # (e.g., refresh/retry or redirect edge cases). Avoid FastAPI 422.
    if not csrf_token or not username or not password:
        page_token = csrf.ensure_csrf_token(request)
        response = templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Thiếu dữ liệu đăng nhập. Vui lòng nhập lại.",
                "csrf_token": page_token,
            },
        )
        csrf.set_csrf_cookie(response, request, page_token)
        response.headers["Cache-Control"] = "no-store"
        return response

    try:
        csrf.validate_csrf(request, csrf_token)
    except Exception:
        new_token = csrf.generate_csrf_token()
        response = templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "CSRF token không hợp lệ. Vui lòng tải lại trang và thử lại.",
                "csrf_token": new_token,
            },
        )
        csrf.set_csrf_cookie(response, request, new_token)
        response.headers["Cache-Control"] = "no-store"
        return response

    try:
        logger.info(
            'Login attempt',
            extra = {'username': username, 'ip': request.client.host}
        )
        user_db = _get_user_by_identifier(username, db)
    except RuntimeError as exc:
        db.rollback()
        page_token = csrf.ensure_csrf_token(request)
        response = templates.TemplateResponse("login.html", {
            "request": request,
            "error": str(exc),
            "csrf_token": page_token,
        })
        csrf.set_csrf_cookie(response, request, page_token)
        response.headers["Cache-Control"] = "no-store"
        return response

    if not user_db:
        
        log_security_event(
            event_type = 'login_failed',
            severity = 'warning',
            user_id = None,
            ip_address=request.client.host,
            details={'username': username, 'reason': 'user_not_found'}
        )
        page_token = csrf.ensure_csrf_token(request)
        response = templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Thông tin đăng nhập không đúng",
            "csrf_token": page_token,
        })
        csrf.set_csrf_cookie(response, request, page_token)
        response.headers["Cache-Control"] = "no-store"
        return response

    is_valid = crypto.verify(password, user_db.password)

    if not is_valid:
        
        log_security_event(
            event_type = 'login_failed',
            severity='warning',
            user_id=user_db.id,
            ip_address=request.client.host,
            details={'reason': 'invalid_password'}
        )
        
        page_token = csrf.ensure_csrf_token(request)
        response = templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Email hoặc mật khẩu không đúng",
            "csrf_token": page_token,
        })
        csrf.set_csrf_cookie(response, request, page_token)
        response.headers["Cache-Control"] = "no-store"
        return response

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

    response = RedirectResponse(url="/user_service/welcome", status_code=303)
    secure_cookie = csrf.is_https_request(request)

    # Standard practice: store auth in cookies (avoid returning a post body for /login).
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key="user_id",
        value=str(user_db.id),
        httponly=False,
        secure=secure_cookie,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key="display_name",
        value=display_name,
        httponly=False,
        secure=secure_cookie,
        samesite="lax",
        path="/",
    )

    response.headers["Cache-Control"] = "no-store"

    # Rotate CSRF token after login (common best practice).
    new_csrf = csrf.generate_csrf_token()
    csrf.set_csrf_cookie(response, request, new_csrf)
    return response


@router.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    # Always render login form for GET /login.
    page_token = csrf.ensure_csrf_token(request)
    response = templates.TemplateResponse(
        "login.html",
        {"request": request, "error": None, "csrf_token": page_token},
    )
    csrf.set_csrf_cookie(response, request, page_token)
    response.headers["Cache-Control"] = "no-store"
    return response


def _logout_response(request: Request) -> RedirectResponse:
    response = RedirectResponse(url="/user_service/login", status_code=303)

    for cookie_name in ("access_token", "user_id", "display_name", csrf.CSRF_COOKIE_NAME):
        response.delete_cookie(cookie_name, path="/")

    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/logout")
async def logout_post(request: Request):
    return _logout_response(request)


@router.get("/logout")
async def logout_get(request: Request):
    return _logout_response(request)


@router.get("/welcome", response_class=HTMLResponse)
async def welcome_get(request: Request):
    token = request.cookies.get("access_token")
    if not token or not oauth2.verify_access_token(token):
        return RedirectResponse(url="/user_service/login", status_code=303)

    # Render welcome page after PRG redirect. Do not embed tokens in HTML.
    display_name = request.cookies.get("display_name")
    user_id = request.cookies.get("user_id")

    response = templates.TemplateResponse(
        "welcome.html",
        {
            "request": request,
            "username": display_name or "",
            "access_token": None,
            "user_id": user_id,
        },
    )
    response.headers["Cache-Control"] = "no-store"
    return response

@router.get("/register", response_class=HTMLResponse)
async def register_get(request: Request):
    page_token = csrf.ensure_csrf_token(request)
    response = templates.TemplateResponse(
        "register.html",
        {"request": request, "error": None, "csrf_token": page_token},
    )
    csrf.set_csrf_cookie(response, request, page_token)
    response.headers["Cache-Control"] = "no-store"
    return response

@router.post("/register", response_class=JSONResponse)
async def register_post(
    request: Request,
    csrf_token: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        csrf.validate_csrf(request, csrf_token)
    except Exception:
        new_token = csrf.generate_csrf_token()
        response = JSONResponse(
            status_code=403,
            content={"success": False, "error": "CSRF token không hợp lệ. Vui lòng tải lại trang."},
        )
        csrf.set_csrf_cookie(response, request, new_token)
        response.headers["Cache-Control"] = "no-store"
        return response
    
    normalized_name = _normalize(name)
    normalized_email = _normalize(email).lower()
    normalized_phone = _normalize_phone(phone)
    if not normalized_phone:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Số điện thoại không hợp lệ"}
        )
    if len(normalized_phone) < 8 or len(normalized_phone) > 15:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Số điện thoại phải có từ 8 đến 15 chữ số"}
        )
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
                return JSONResponse(
                    status_code=400,
                    content={"success": False, "error": str(exc)}
                )
    if exists_email:
        logger.warning("Registration attempted with existing email")
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Email đã tồn tại"}
        )

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
                return JSONResponse(
                    status_code=400,
                    content={"success": False, "error": str(exc)}
                )
    if exists_phone:
        logger.warning("Registration attempted with existing phone")
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Số điện thoại đã tồn tại"}
        )
    
    if password != confirm_password:
        logger.info("Registration rejected: password mismatch")
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Mật khẩu không khớp"}
        )
    
    if len(password) < 6:
        logger.info("Registration rejected: password too short")
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Mật khẩu phải có ít nhất 6 ký tự"}
        )
    
    # Gửi OTP để xác thực email
    try:
        otp_sent = otp_service.send_registration_otp(normalized_email, normalized_name)
        if not otp_sent:
            return JSONResponse(
                status_code=500,
                content={"success": False, "error": "Không thể gửi mã OTP. Vui lòng thử lại sau."}
            )
        
        # Lưu thông tin đăng ký tạm thời (5 phút)
        hashed_pass = crypto.hash(password)
        try:
            name_encrypted = _encrypt_value(normalized_name, _name_aad(name_hash))
            email_encrypted = _encrypt_value(normalized_email, _email_aad(email_hash))
            phone_encrypted = _encrypt_value(normalized_phone, _phone_aad(phone_hash))
        except RuntimeError as exc:
            return JSONResponse(
                status_code=500,
                content={"success": False, "error": str(exc)}
            )
        
        registration_data = {
            "name": normalized_name,
            "name_hash": name_hash,
            "name_encrypted": name_encrypted,
            "email": normalized_email,
            "email_hash": email_hash,
            "email_encrypted": email_encrypted,
            "phone": normalized_phone,
            "phone_hash": phone_hash,
            "phone_encrypted": phone_encrypted,
            "password_hash": hashed_pass,
            "timestamp": time.time()
        }
        
        # Lưu vào Redis hoặc memory
        reg_key = f"registration:{normalized_email}"
        if otp_service.redis_client:
            otp_service.redis_client.setex(reg_key, 300, json.dumps(registration_data))  # 5 phút
        else:
            if not hasattr(otp_service, '_registration_storage'):
                otp_service._registration_storage = {}
            otp_service._registration_storage[reg_key] = registration_data
        
        logger.info("Registration OTP sent")
        return JSONResponse(
            content={
                "success": True,
                "message": "Mã OTP đã được gửi đến email của bạn. Vui lòng kiểm tra email và nhập mã xác thực.",
                "email": normalized_email
            }
        )
        
    except Exception as e:
        logger.exception("Registration OTP send failed")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"Lỗi server: {str(e)}"}
        )


@router.post("/verify-registration-otp", response_class=JSONResponse)
async def verify_registration_otp(
    request: Request,
    csrf_token: str = Form(...),
    email: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_db)
):
    """Xác thực OTP và hoàn tất đăng ký tài khoản"""
    try:
        csrf.validate_csrf(request, csrf_token)
        normalized_email = _normalize(email).lower()
        is_valid = otp_service.verify_registration_otp(normalized_email, otp)
        if not is_valid:
            return JSONResponse(status_code=400, content={"success": False, "error": "Mã OTP không đúng hoặc đã hết hạn"})
        
        # Retrieve registration data
        reg_key = f"registration:{normalized_email}"
        registration_data = None
        if otp_service.redis_client:
            try:
                data_json = otp_service.redis_client.get(reg_key)
                if data_json:
                    registration_data = json.loads(data_json)
                    otp_service.redis_client.delete(reg_key)
            except Exception as e:
                logger.warning("Redis get failed during registration OTP verify", exc_info=True)
        
        if not registration_data and hasattr(otp_service, '_registration_storage'):
            if reg_key in otp_service._registration_storage:
                registration_data = otp_service._registration_storage[reg_key]
                del otp_service._registration_storage[reg_key]
        
        if not registration_data:
            return JSONResponse(status_code=400, content={"success": False, "error": "Phiên đăng ký đã hết hạn. Vui lòng đăng ký lại."})
        
        # Check email and phone again (in case someone else claimed during wait)
        email_hash = registration_data["email_hash"]
        phone_hash = registration_data["phone_hash"]
        existing_email = db.query(User).filter(User.email == email_hash).first()
        if existing_email:
            return JSONResponse(status_code=400, content={"success": False, "error": "Email đã được đăng ký bởi người khác"})
        existing_phone = db.query(User).filter(User.phone == phone_hash).first()
        if existing_phone:
            return JSONResponse(status_code=400, content={"success": False, "error": "Số điện thoại đã được đăng ký bởi người khác"})
        
        # Create user with email_verified = 1
        new_user = User(
            name=registration_data["name_hash"],
            email=registration_data["email_hash"],
            password=registration_data["password_hash"],
            name_encrypted=registration_data["name_encrypted"],
            email_encrypted=registration_data["email_encrypted"],
            phone=registration_data["phone_hash"],
            phone_encrypted=registration_data["phone_encrypted"],
            email_verified=1
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info("User registered successfully", extra={"user_id": str(new_user.id)})
        
        return JSONResponse(content={"success": True, "message": "Đăng ký tài khoản thành công! Bạn có thể đăng nhập ngay.", "redirect": "/"})
    
    except Exception as e:
        logger.exception("Error in verify_registration_otp")
        db.rollback()
        return JSONResponse(status_code=500, content={"success": False, "error": f"Lỗi server: {str(e)}"})


# API endpoint to get user information by ID
@router.get("/users/{user_id}")
async def get_user_info(user_id: int, db: Session = Depends(get_db)):
    """
    Get user information by user ID.
    Returns decrypted email for display purposes.
    """
    try:
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            return JSONResponse(status_code=404, content={"error": "User not found"})
        
        # Decrypt email
        try:
            email_payload = json.loads(user.email_encrypted)
            email_aad = f"user:email:{user.email}".encode("utf-8")
            decrypted_email = AESEncryption.decrypt_aes_gcm(
                email_payload,
                _get_user_encryption_key(),
                email_aad
            )
            
            # Return user info with decrypted email
            return JSONResponse(content={
                "id": user.id,
                "username": user.username,
                "email": decrypted_email,
                "email_verified": user.email_verified
            })
        except Exception as decrypt_error:
            logger.exception("Error decrypting email for user", extra={"user_id": str(user_id)})
            return JSONResponse(status_code=500, content={"error": "Failed to decrypt user email"})
            
    except Exception as e:
        logger.exception("Error in get_user_info", extra={"user_id": str(user_id)})
        return JSONResponse(status_code=500, content={"error": f"Server error: {str(e)}"})