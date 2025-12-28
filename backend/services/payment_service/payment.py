from fastapi import APIRouter, Form, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from dotenv import load_dotenv
import stripe
from sqlalchemy.orm import Session
from backend.database.database import get_db
from backend.models.models import User, PaymentHistory
from backend.services.payment_service.security.encryption import AESEncryption
import os
import hmac
import time
import json
import traceback
import hashlib
import base64
from typing import Optional
from backend.config.config import settings
from backend.services.payment_service.security.hsm_client import (
    sign_data,
    generate_secure_random,
)
import email
from backend.oauth2.oauth2 import verify_access_token
from backend.services.payment_service.security.hsm_client import HSMError
from backend.services.payment_service.security.tokenization import card_tokenizer
from backend.services.payment_service.security.encryption import DataMasking
from backend.services.payment_service.security.fraud_detection import (
    FraudDetector,
    TransactionInput,
)



from backend.utils.logger import (
    get_application_logger,
    log_payment_attempt,
    log_security_event,
    get_error_logger,
    get_transaction_logger,
    log_audit_trail,
)

logger = get_transaction_logger(__name__)


def _demo_security_apis_enabled() -> bool:
    return (os.getenv("ENABLE_DEMO_SECURITY_APIS") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _require_demo_security_apis_enabled() -> None:
    # Hide these routes by default to avoid accidental PAN/CVV handling in prod.
    if not _demo_security_apis_enabled():
        raise HTTPException(status_code=404, detail="Not found")


def _stripe_card_summary_from_intent(intent: object) -> Optional[dict]:
    """Best-effort extraction of non-sensitive card summary from Stripe response."""
    try:
        charges = getattr(intent, "charges", None)
        data = getattr(charges, "data", None) if charges else None
        if not data:
            return None
        charge0 = data[0]
        pm_details = getattr(charge0, "payment_method_details", None)
        card = getattr(pm_details, "card", None) if pm_details else None
        if not card:
            return None

        last4 = getattr(card, "last4", None)
        brand = getattr(card, "brand", None)
        exp_month = getattr(card, "exp_month", None)
        exp_year = getattr(card, "exp_year", None)
        if not last4 and not brand:
            return None
        return {
            "masked": f"**** **** **** {last4}" if last4 else None,
            "brand": brand,
            "exp_month": exp_month,
            "exp_year": exp_year,
        }
    except Exception:
        return None


def _get_authenticated_user_id(request: Request) -> Optional[int]:
    """Best-effort auth: Authorization: Bearer <jwt> OR cookie access_token."""
    token: Optional[str] = None

    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        parts = auth.split()
        if len(parts) == 2:
            token = parts[1]

    if not token:
        token = request.cookies.get("access_token")

    if not token:
        return None

    token_data = verify_access_token(token)
    user_id = None
    if token_data:
        user_id = getattr(token_data, "id", None)
        if user_id is None:
            user_id = getattr(token_data, "user_id", None)
    if not token_data or user_id is None:
        return None
    try:
        return int(user_id)
    except Exception:
        return None

# =========================
# HELPER FUNCTIONS FOR USER DATA DECRYPTION
# =========================
USER_AES_KEY_ENV = "USER_AES_KEY"
LEGACY_AES_KEY_ENV = "Key_AES"
_USER_AES_KEY_CACHE = None

def _get_user_encryption_key() -> bytes:
    global _USER_AES_KEY_CACHE
    if _USER_AES_KEY_CACHE is not None:
        return _USER_AES_KEY_CACHE

    key_b64 = os.getenv(USER_AES_KEY_ENV) or os.getenv(LEGACY_AES_KEY_ENV)
    if not key_b64:
        raise RuntimeError(
            "USER_AES_KEY environment variable is required to decrypt user data."
        )

    try:
        key = base64.b64decode(key_b64)
    except Exception as exc:
        raise RuntimeError("USER_AES_KEY must be base64 encoded.") from exc

    if len(key) != 32:
        raise RuntimeError("USER_AES_KEY must decode to 32 bytes (AES-256 key length).")

    _USER_AES_KEY_CACHE = key
    return key

def _email_aad(email_hash: str) -> bytes:
    return f"user:email:{email_hash}".encode("utf-8")

def _decrypt_email(user_obj: User) -> str:
    """Decrypt user email from database"""
    if not user_obj.email_encrypted:
        print(f"⚠️ No email_encrypted for user {user_obj.id}")
        return None
    try:
        print(f"🔐 Attempting to decrypt email for user {user_obj.id}")
        print(f"   email_hash: {user_obj.email}")
        print(f"   email_encrypted (first 50 chars): {user_obj.email_encrypted[:50]}...")
        payload = json.loads(user_obj.email_encrypted)
        email = AESEncryption.decrypt_aes_gcm(payload, _get_user_encryption_key(), _email_aad(user_obj.email))
        print(f"✅ Successfully decrypted email: {email[:5]}***@{email.split('@')[1] if '@' in email else '***'}")
        return email
    except Exception as e:
        print(f"❌ Error decrypting email for user {user_obj.id}: {e}")
        traceback.print_exc()
        return None

# =========================
# CẤU HÌNH & KHỞI TẠO
# =========================
ROOT_DIR = Path(__file__).resolve().parents[3]
load_dotenv(dotenv_path=ROOT_DIR / ".env")

STRIPE_PUBLIC_KEY = settings.Stripe_Public_Key
STRIPE_SECRET_KEY = settings.Stripe_Secret_Key

# Only fail if Stripe is actually used, not at import time
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
    print("✅ Stripe configured")
else:
    print("⚠️ STRIPE_SECRET_KEY not configured - payments will fail")
    
templates = Jinja2Templates(directory=str(ROOT_DIR / "frontend" / "templates"))

# =========================
# MOCK DATA (trường hợp test)
# =========================
try:
    from backend.services.order_service.order import MOCK_ORDERS, CART
except Exception:
    MOCK_ORDERS = [
        {
            "id": "ORD-DEMO-01",
            "description": "Product A",
            "amount": 150000,
            "currency": "vnd",
        },
        {
            "id": "ORD-DEMO-02",
            "description": "Product B",
            "amount": 300000,
            "currency": "vnd",
        },
    ]
    CART = []

TEMP_CART_ORDER: dict[str, dict] = {}
router = APIRouter(tags=["Payment Service"])

# =========================
# CHECKOUT CONTEXT SIGNING (anti-tamper)
# =========================
_CHECKOUT_SIGNING_SECRET = os.getenv("CHECKOUT_SIGNING_SECRET") or getattr(
    settings, "secret_key", ""
)


def _canonical_currency(currency: Optional[str]) -> str:
    return (currency or "vnd").strip().lower()


def _canonical_amount(amount: object) -> str:
    # Avoid float canonicalization issues: VND is integer in this demo.
    return str(int(amount))


def _checkout_sig_payload(order_id: str, amount: object, currency: Optional[str]) -> bytes:
    # Stable, unambiguous payload
    return f"{order_id}|{_canonical_amount(amount)}|{_canonical_currency(currency)}".encode(
        "utf-8"
    )


def _sign_checkout_context(order_id: str, amount: object, currency: Optional[str]) -> str:
    if not _CHECKOUT_SIGNING_SECRET:
        # Should never happen, but keep behavior explicit.
        raise RuntimeError("CHECKOUT_SIGNING_SECRET/settings.secret_key not configured")
    payload = _checkout_sig_payload(order_id, amount, currency)
    return hmac.new(
        _CHECKOUT_SIGNING_SECRET.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()


def _verify_checkout_context_sig(sig: str, order_id: str, amount: object, currency: Optional[str]) -> bool:
    try:
        expected = _sign_checkout_context(order_id, amount, currency)
    except Exception:
        return False
    return hmac.compare_digest((sig or "").strip(), expected)


def _get_order_by_id(order_id: str) -> Optional[dict]:
    order = next((o for o in MOCK_ORDERS if o.get("id") == order_id), None)
    if order:
        return order
    return TEMP_CART_ORDER.get(order_id)

# =========================
# KHỞI TẠO FRAUD DETECTOR
# =========================
fraud_detector = FraudDetector()

from backend.services.payment_service.otp_service import OTPService

try:
    from backend.middleware.rate_limiter import redis_client, USE_REDIS

    if USE_REDIS:
        otp_service = OTPService(redis_client)
        print("✅ OTP Service initialized with Redis")
    else:
        otp_service = OTPService(None)
        print("⚠️ OTP Service initialized (memory-only)")
except Exception as e:
    print(f"⚠️ OTP Service initialization failed: {e}")
    otp_service = OTPService(None)
    print("⚠️ OTP Service initialized (fallback)")


# =========================
# HÀM KÝ BIÊN LAI BẰNG HSM
# =========================
def create_signed_receipt(transaction_data: dict) -> dict:
    """Ký biên lai thanh toán bằng HSM nếu có; fallback phần mềm nếu HSM không khả dụng."""
    payload = json.dumps(transaction_data, sort_keys=True).encode()
    try:
        signature = sign_data(payload, key_label="DemoKey")  # 🔐 Ký thật bằng HSM
        return {"signed_receipt": signature, "signed_by": "HSM-DemoKey"}
    except (HSMError, Exception):
        # Fallback an toàn: dùng SHA-256 làm dấu vết + random salt (KHÔNG thay thế chữ ký thật)
        salt = os.urandom(16)
        digest = hashlib.sha256(salt + payload).digest()
        soft_sig = base64.b64encode(digest).decode()
        return {"signed_receipt": soft_sig, "signed_by": "SOFTWARE-FALLBACK"}


# =========================
# ERROR CODES MAPPING
# =========================
ERROR_CODES = {
    "CARD_DECLINED": "E001",           # Thẻ bị từ chối
    "INSUFFICIENT_FUNDS": "E002",      # Không đủ tiền
    "INVALID_CARD": "E003",            # Thẻ không hợp lệ
    "EXPIRED_CARD": "E004",            # Thẻ đã hết hạn
    "INVALID_CVV": "E005",             # CVV không hợp lệ
    "INVALID_REQUEST": "E006",         # Yêu cầu không hợp lệ
    "STRIPE_ERROR": "E007",            # Lỗi Stripe
    "INTERNAL_ERROR": "E008",          # Lỗi server nội bộ
    "PAYMENT_INCOMPLETE": "E009",      # Thanh toán không hoàn thành
    "DUPLICATE_TRANSACTION": "E010",   # Giao dịch trùng lặp
}

# =========================
# API ROUTES
# =========================
@router.get("/healthz")
async def health_check():
    return {"status": "ok", "service": "payment_service"}


# =========================
# SECURITY APIS (Tokenization demo)
# =========================
@router.post("/security/tokenize_card")
async def tokenize_card(
    card_number: str = Form(...),
    cvv: str = Form(...),
    expiry: str = Form(...),
    cardholder_name: str = Form(...),
):
    """Nhận dữ liệu thẻ và trả về token cùng số thẻ đã che (demo học tập)."""
    _require_demo_security_apis_enabled()
    try:
        result = card_tokenizer.generate_token(
            card_number, cvv, expiry, cardholder_name
        )
        masked = DataMasking.mask_card_number(card_number)
        return {
            "token": result["token"],
            "masked_card": masked,
            "card_brand": result["card_brand"],
            "fingerprint": result["fingerprint"],
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/security/token_info")
async def token_info(token: str):
    """Trả về thông tin an toàn về token (KHÔNG trả số thẻ gốc)."""
    _require_demo_security_apis_enabled()
    try:
        data = card_tokenizer.detokenize(token)
        masked = DataMasking.mask_card_number(data["card_number"]) if data else None
        return {"token": token, "masked_card": masked, "exists": data is not None}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/security/delete_token")
async def delete_token(token: str = Form(...)):
    _require_demo_security_apis_enabled()
    ok = card_tokenizer.delete_token(token)
    if not ok:
        raise HTTPException(status_code=404, detail="Token not found")
    return {"deleted": True}


@router.get("/checkout", response_class=HTMLResponse)
async def checkout_single_order(request: Request, order_id: str, db: Session = Depends(get_db)):
    order = next((o for o in MOCK_ORDERS if o["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    order["currency"] = order.get("currency", "vnd").lower()

    checkout_sig = _sign_checkout_context(order["id"], order.get("amount"), order.get("currency"))
    
    return templates.TemplateResponse(
        "checkout.html",
        {
            "request": request,
            "order": order,
            "checkout_sig": checkout_sig,
            "stripe_public_key": STRIPE_PUBLIC_KEY,
        },
    )


@router.get("/checkout_cart", response_class=HTMLResponse)
async def checkout_cart(request: Request, db: Session = Depends(get_db)):
    global TEMP_CART_ORDER
    if not CART:
        raise HTTPException(status_code=400, detail="Cart is empty")

    total = sum(int(i["amount"]) for i in CART)
    order_id = f"CART-{os.urandom(4).hex().upper()}"

    TEMP_CART_ORDER[order_id] = {
        "id": order_id,
        "amount": total,
        "currency": "vnd",
        "description": f"{len(CART)} items in cart",
        "status": "PENDING",
    }

    checkout_sig = _sign_checkout_context(
        TEMP_CART_ORDER[order_id]["id"],
        TEMP_CART_ORDER[order_id].get("amount"),
        TEMP_CART_ORDER[order_id].get("currency"),
    )

    return templates.TemplateResponse(
        "checkout.html",
        {
            "request": request,
            "order": TEMP_CART_ORDER[order_id],
            "checkout_sig": checkout_sig,
            "stripe_public_key": STRIPE_PUBLIC_KEY,
        },
    )


@router.post("/request_otp")
async def request_otp(
    request: Request,
    order_id: str = Form(...),
    checkout_sig: str = Form(...),
    amount: Optional[float] = Form(None),
    currency: str = Form(default="vnd"),
    user_id: Optional[int] = Form(None),
    db: Session = Depends(get_db),
):
    """
    Gửi mã OTP qua Gmail đến email đã đăng ký của user

    Flow:
    1. Lấy user_id từ localStorage (frontend gửi lên)
    2. Tìm email đã đăng ký trong database
    3. Gửi OTP đến email đó
    4. User nhập OTP để xác thực thanh toán
    """
    print("="*60)
    print("🎯 REQUEST_OTP endpoint called!")
    print(f"   user_id: {user_id}")
    print(f"   order_id: {order_id}")
    print(f"   amount(client): {amount}")
    print(f"   currency(client): {currency}")
    print("="*60)
    
    if not otp_service:
        return {"success": False, "message": "OTP service not available"}

    auth_user_id = _get_authenticated_user_id(request)
    if not auth_user_id:
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": "Vui lòng đăng nhập để tiếp tục thanh toán"},
        )

    if user_id is not None and int(user_id) != int(auth_user_id):
        log_security_event(
            event_type="idor_blocked",
            severity="warning",
            user_id=str(auth_user_id),
            ip_address=request.client.host if request.client else None,
            details={"endpoint": "request_otp", "submitted_user_id": int(user_id)},
        )
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "message": "Forbidden: user mismatch. Please logout/login and clear stale localStorage/cookies.",
            },
        )

    order = _get_order_by_id(order_id)
    if not order:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "Order not found"},
        )

    # Always derive amount/currency from server-side order data
    order_currency = _canonical_currency(order.get("currency"))
    order_amount = int(order.get("amount") or 0)

    if not _verify_checkout_context_sig(checkout_sig, order_id, order_amount, order_currency):
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "message": "Dữ liệu đơn hàng không hợp lệ (order_id bị thay đổi). Vui lòng tải lại trang checkout.",
            },
        )

    # Tìm user trong database
    user = db.query(User).filter(User.id == int(auth_user_id)).first()
    if not user:
        return {"success": False, "message": "Không tìm thấy thông tin người dùng"}

    # Giải mã email
    email = _decrypt_email(user)
    if not email:
        return {"success": False, "message": "Lỗi xử lý thông tin người dùng"}

    # Không gửi OTP tại đây - OTP sẽ được gửi sau fraud detection trong create_payment
    return {
        "success": True,
        "message": f"Thông tin xác thực hợp lệ. Vui lòng tiếp tục thanh toán.",
        "email_masked": email[:3] + "***@" + email.split("@")[1] if "@" in email else "***",
    }


@router.post("/verify_otp")
async def verify_otp(
    request: Request,
    otp: str = Form(...),
    order_id: str = Form(...),
    checkout_sig: str = Form(...),
    amount: Optional[float] = Form(None),
    currency: str = Form(default="vnd"),
    user_id: Optional[int] = Form(None),
    db: Session = Depends(get_db),
):
    """
    Xác thực OTP trước khi cho phép nhập thông tin thẻ.
    - Frontend gọi: /payment_service/verify_otp
    - FormData: otp, order_id, amount, currency, user_id
    """
    print("="*60)
    print("🔍 VERIFY_OTP endpoint called!")
    print(f"   user_id: {user_id}")
    print(f"   order_id: {order_id}")
    print(f"   otp: {otp}")
    print("="*60)
    
    if not otp_service:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "OTP service not available"},
        )

    auth_user_id = _get_authenticated_user_id(request)
    if not auth_user_id:
        return JSONResponse(
            status_code=401,
            content={"success": False, "error": "Vui lòng đăng nhập để tiếp tục"},
        )

    if user_id is not None and int(user_id) != int(auth_user_id):
        log_security_event(
            event_type="idor_blocked",
            severity="warning",
            user_id=str(auth_user_id),
            ip_address=request.client.host if request.client else None,
            details={"endpoint": "verify_otp", "submitted_user_id": int(user_id)},
        )
        return JSONResponse(
            status_code=403,
            content={
                "success": False,
                "error": "Forbidden: user mismatch. Please logout/login and clear stale localStorage/cookies.",
            },
        )

    order = _get_order_by_id(order_id)
    if not order:
        return JSONResponse(
            status_code=404,
            content={"success": False, "error": "Order not found"},
        )

    order_currency = _canonical_currency(order.get("currency"))
    order_amount = int(order.get("amount") or 0)
    if not _verify_checkout_context_sig(checkout_sig, order_id, order_amount, order_currency):
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": "Dữ liệu đơn hàng không hợp lệ (order_id bị thay đổi). Vui lòng tải lại trang checkout.",
            },
        )

    # Tìm user trong database
    user = db.query(User).filter(User.id == int(auth_user_id)).first()
    if not user:
        return JSONResponse(
            status_code=404,
            content={"success": False, "error": "Không tìm thấy thông tin người dùng"},
        )

    # Giải mã email
    email = _decrypt_email(user)
    if not email:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "Lỗi xử lý thông tin người dùng"},
        )

    # Xác thực OTP
    is_valid = otp_service.verify_otp(email, order_id, otp)

    if not is_valid:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Mã OTP không đúng hoặc đã hết hạn."},
        )


    return {"success": True, "message": "OTP hợp lệ. Bạn có thể tiếp tục thanh toán."}

from sqlalchemy.orm import Session
from fastapi import Depends
from backend.database.database import get_db
from backend.models import models as db_models
# =========================
# XỬ LÝ THANH TOÁN
# =========================
@router.post("/create_payment")
async def create_payment(
    request: Request,
    payment_token: str = Form(...),
    order_id: str = Form(...),
    checkout_sig: str = Form(...),
    nonce: str = Form(...),
    device_fingerprint: str = Form(...),
    otp: str = Form(...),  # OTP code from user - BẮT BUỘC
    user_id: Optional[int] = Form(None),  # Optional; validated against JWT
    db: Session = Depends(get_db),
):
    # Log initial payment request safely (handle missing client)
    client_ip = request.client.host if request.client else None
    logger.info(
        "Payment request received", extra={"order_id": order_id, "ip": client_ip}
    )

    global TEMP_CART_ORDER, CART

    order = _get_order_by_id(order_id)
    if not order:
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": "Order not found"}
        )

    # Enforce anti-tamper signature: prevents swapping order_id to change amount
    order_currency = _canonical_currency(order.get("currency"))
    order_amount = int(order.get("amount") or 0)
    if not _verify_checkout_context_sig(checkout_sig, order_id, order_amount, order_currency):
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": "Invalid checkout context. Please reload checkout page.",
            },
        )

    logger.info(
        "Payment processing initiated for order",
        extra={
            "order_id": order_id,
            "amount": order["amount"],
            "currency": order["currency"],
        },
    )

    try:
        from backend.middleware.rate_limiter import redis_client, USE_REDIS

        if USE_REDIS:
            nonce_key = f"nonce:{nonce}"
            
            # SỬA: Dùng set với tham số nx=True (Atomic)
            # Lệnh này trả về True nếu set thành công (key chưa có)
            # Trả về False nếu set thất bại (key đã có)
            is_new_nonce = redis_client.set(nonce_key, "used", ex=86400, nx=True)
            
            if not is_new_nonce:
                # Nếu trả về False nghĩa là đã có người khác chiếm trước rồi
                return templates.TemplateResponse(
                    "error.html",
                    {
                        "request": request,
                        "error": "⚠️ Giao dịch bị trùng lặp (Race Condition blocked)!",
                    },
                )
             
            print(f"✅ Nonce validated and stored atomically: {nonce[:8]}...")
        else:
            print("⚠️ Nonce validation skipped - Redis unavailable")
    except Exception as e:
        print(f"⚠️ Nonce validation error: {e}")

    # =========================
    # 🛡️ FRAUD DETECTION CHECK
    # =========================
    client_ip = request.client.host if request.client else None
    auth_user_id = _get_authenticated_user_id(request)
    user_db = db.query(db_models.User).filter(db_models.User.id == int(auth_user_id)).first() if auth_user_id else None
    fraud_user_id = str(user_db.id) if user_db else str(auth_user_id)
    fraud_check = TransactionInput(
        user_id=fraud_user_id,
        amount=(float(order["amount"]) / 100 if order["currency"] == "vnd" else float(order["amount"])),
        currency=order["currency"],
        ip_address=client_ip,
        billing_country="VN",
    )
    fraud_result = fraud_detector.assess_transaction(fraud_check)

    # Nếu phát hiện fraud (score cao hoặc rule cứng), chặn giao dịch
    if fraud_result.is_fraud:
        log_security_event(
            event_type="fraud_blocked",
            severity="critical",
            user_id=order_id,
            ip_address=request.client.host,
            details={
                "fraud_score": fraud_result.score,
                "rules": fraud_result.triggered_rules,
            },
        )
        log_audit_trail(
            action="payment_blocked",
            actor_user_id=str(order_id),
            target=f"order:{order_id}",
            details={
                "fraud_score": fraud_result.score,
                "rules": fraud_result.triggered_rules,
            },
        )
        return JSONResponse(
            status_code=403,
            content={"success": False, "error": f"⚠️ Transaction blocked: {fraud_result.message} (Score: {fraud_result.score:.2f})"},
        )

    # Nếu score ở mức trung bình (0.4 <= score < 0.75), yêu cầu OTP
    if 0.4 <= fraud_result.score < 0.75:
        # Nếu chưa có OTP, trả về yêu cầu OTP (và gửi OTP)
        if not otp:
            user = db.query(User).filter(User.id == int(auth_user_id)).first() if auth_user_id else None
            email = _decrypt_email(user) if user else None
            otp_sent = False
            if email:
                otp_service.send_otp(email, float(order["amount"]), order["currency"], order_id)
                otp_sent = True
            return JSONResponse(
                status_code=200,
                content={
                    "success": False,
                    "require_otp": True,
                    "message": "Giao dịch cần xác thực OTP. OTP đã được gửi đến email của bạn." if otp_sent else "Giao dịch cần xác thực OTP. Không thể gửi OTP.",
                },
            )
        # Nếu đã có OTP, xác thực OTP
        user = db.query(User).filter(User.id == int(auth_user_id)).first() if auth_user_id else None
        email = _decrypt_email(user) if user else None
        if not email:
            return JSONResponse(
                status_code=404,
                content={"success": False, "error": "Không tìm thấy thông tin người dùng"},
            )
        is_valid = otp_service.verify_otp(email, order_id, otp)
        if not is_valid:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Mã OTP không đúng hoặc đã hết hạn."},
            )
        # Nếu OTP hợp lệ, tiếp tục thanh toán
    
    auth_user_id = _get_authenticated_user_id(request)
    if not auth_user_id:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": "❌ Vui lòng đăng nhập để tiếp tục thanh toán!",
            },
        )

    if user_id is not None and int(user_id) != int(auth_user_id):
        log_security_event(
            # Nếu score thấp (< 0.4), cho phép thanh toán luôn
            # ...existing code...
            {
                "request": request,
                "order_id": order_id,
                "message": "Vui lòng nhập mã OTP để xác thực thanh toán!",
            },
        )


    # =========================
    # RACE CONDITION PREVENTION - DB LOCKING
    # =========================
    # Note: DB locking bị tạm thời disable vì đang dùng MOCK_ORDERS
    # Nếu muốn enable, cần thêm field 'order_id' (string) vào model Order
    try:
        pass  # Skip DB locking for MOCK_ORDERS
        # current_order_db = db.query(db_models.Order).filter(
        #     db_models.Order.id == order_id  # Cần convert order_id string sang int
        # ).with_for_update().first()
        # ... (rest of locking logic)
    except Exception as e:
        print(f"⚠️ Error during DB Locking: {e}")
        # Don't fail the payment just because of locking error
        pass

    # =========================
    # XỬ LÝ THANH TOÁN VỚI STRIPE
    # =========================
    try:
        # Check Stripe configuration at runtime
        if not STRIPE_SECRET_KEY:
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": "❌ Payment service not configured. Please contact administrator.",
                    "error_code": ERROR_CODES["INTERNAL_ERROR"],
                },
                status_code=503,
            )
        
        # Generate idempotency key (order_id + nonce for uniqueness)
        idempotency_key = f"order_{order_id}_nonce_{nonce}"
        intent = stripe.PaymentIntent.create(
            amount=order["amount"],
            currency=order["currency"],
            description=order["description"],
            payment_method_data={"type": "card", "card": {"token": payment_token}},
            confirm=True,
            capture_method="manual",
            return_url="http://127.0.0.1:8000/success_payment",
            metadata={"order_id": order_id},
            idempotency_key=idempotency_key
        )

        # Sau khi intent được tạo, chạy fraud check
        fraud_result = fraud_detector.assess_transaction(fraud_check)
        if fraud_result.is_fraud:
            # Nếu nghi ngờ, cancel intent
            try:
                stripe.PaymentIntent.cancel(intent.id)
            except Exception as e:
                logger.error(f"Failed to cancel PaymentIntent {intent.id}: {e}")
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": f"\u26a0\ufe0f Transaction blocked: {fraud_result.message} (Score: {fraud_result.score:.2f})",
                },
            )
        else:
            # Nếu an toàn, capture intent và cập nhật intent status
            try:
                intent = stripe.PaymentIntent.capture(intent.id)
            except Exception as e:
                logger.error(f"Failed to capture PaymentIntent {intent.id}: {e}")

        if intent.status == "succeeded":
            card_summary = _stripe_card_summary_from_intent(intent) or {}
            masked_card = card_summary.get("masked")

            log_payment_attempt(
                transaction_id=intent.id,
                order_id=order_id,
                amount=order["amount"] / 100,
                currency=order["currency"],
                status=intent.status,
                fraud_score=fraud_result.score if fraud_result else None,
                masked_card=masked_card,
            )
            log_audit_trail(
                action="payment_completed",
                actor_user_id=str(intent.id),  # Từ JWT
                target=f"order:{order_id}",
                details={
                    "transaction_id": intent.id,
                    "amount": order["amount"],
                    "currency": order["currency"],
                    "fraud_score": fraud_result.score if fraud_result else None,
                },
            )
            order["status"] = "SUCCESS"

            # Persist customer history to DB (shown next to cart)
            try:
                if auth_user_id:
                    db.add(
                        PaymentHistory(
                            owner_id=int(auth_user_id),
                            external_order_id=str(order_id),
                            amount=int(order.get("amount") or 0),
                            currency=str(order.get("currency") or "VND"),
                            description=str(order.get("description") or ""),
                            status="SUCCESS",
                            stripe_transaction_id=str(intent.id),
                        )
                    )
                    db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass

            # ✅ Tạo nonce an toàn từ HSM (fallback phần mềm nếu HSM không khả dụng)
            try:
                nonce_value = generate_secure_random(12)
            except (HSMError, Exception):
                nonce_value = base64.b64encode(os.urandom(12)).decode()

            # ✅ Dữ liệu biên lai cần ký
            receipt_data = {
                "transaction_id": intent.id,
                "timestamp": int(time.time()),
                "nonce": nonce_value,
            }

            # ✅ Ký biên lai bằng HSM
            signed_receipt = create_signed_receipt(receipt_data)

            # Note: DB order update skipped - using MOCK_ORDERS
            # Uncomment below when using real DB orders with proper order_id mapping
            # try:
            #     converted_amount = float(order["amount"]) / 100 if order["currency"] == "vnd" else float(order["amount"])
            #     current_order_db.status = "SUCCESS"
            #     current_order_db.total_price = converted_amount
            #     db.commit()
            #     db.refresh(current_order_db)
            #     print(f"✅ Order updated in DB: id={current_order_db.id} owner={current_order_db.owner_id} total={converted_amount}")
            # except Exception as e:
            #     print(f"⚠️ Error updating order in DB: {e}")
            #     db.rollback()
                
            if order_id.startswith("CART-"):
                del TEMP_CART_ORDER[order_id]
                CART.clear()

            return templates.TemplateResponse(
                "success.html",
                {
                    "request": request,
                    "receipt": receipt_data,
                    "order": order,
                    "signed_receipt": signed_receipt,
                },
                status_code=200,
            )

        else:
            logger.warning(
                f"Payment incomplete: {intent.status}", extra={"order id": order_id}
            )
            db.rollback()

            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": f"Payment requires confirmation. Status: {intent.status}",
                    "error_code": ERROR_CODES["PAYMENT_INCOMPLETE"],
                },
                status_code=402,
            )

    except stripe.CardError as e:
        body = e.json_body
        err = body.get("error", {})
        error_code = err.get("code", "")
        
        # Map Stripe error codes to our error codes
        if error_code == "card_declined":
            our_error_code = ERROR_CODES["CARD_DECLINED"]
        elif error_code == "insufficient_funds":
            our_error_code = ERROR_CODES["INSUFFICIENT_FUNDS"]
        elif error_code == "invalid_card":
            our_error_code = ERROR_CODES["INVALID_CARD"]
        elif error_code == "expired_card":
            our_error_code = ERROR_CODES["EXPIRED_CARD"]
        elif error_code == "incorrect_cvc":
            our_error_code = ERROR_CODES["INVALID_CVV"]
        else:
            our_error_code = ERROR_CODES["CARD_DECLINED"]
        
        logger.warning(
            f"Card declined: {err.get('message')}",
            extra={"order_id": order_id, "code": error_code},
        )
        db.rollback()
        
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": f"Payment failed: {err.get('message')}",
                "error_code": our_error_code,
            },
            status_code=402,
        )

    except stripe.InvalidRequestError as e:
        logger.error(
            f"Stripe Invalid Request: {e}", exc_info=True, extra={"order_id": order_id}
        )
        db.rollback()
        
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": f"Invalid Data: {e}",
                "error_code": ERROR_CODES["INVALID_REQUEST"],
            },
            status_code=400,
        )

    except Exception as e:
        traceback.print_exc()
        logger.error(
            "Critical error in payment processing",
            exc_info=True,
            extra={"order_id": order_id},
        )
        db.rollback()
        
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": f"Error processing payment: {e}",
                "error_code": ERROR_CODES["INTERNAL_ERROR"],
            },
            status_code=500,
        )
