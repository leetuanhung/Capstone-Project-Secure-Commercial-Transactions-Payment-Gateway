from fastapi import APIRouter, Form, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from dotenv import load_dotenv
import stripe
from sqlalchemy.orm import Session
from backend.database.database import get_db
from backend.models.models import User
from backend.services.payment_service.security.encryption import AESEncryption
import os
import time
import json
import traceback
import hashlib
import base64
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
    try:
        data = card_tokenizer.detokenize(token)
        masked = DataMasking.mask_card_number(data["card_number"]) if data else None
        return {"token": token, "masked_card": masked, "exists": data is not None}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/security/delete_token")
async def delete_token(token: str = Form(...)):
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
    
    return templates.TemplateResponse(
        "checkout.html",
        {"request": request, "order": order, "stripe_public_key": STRIPE_PUBLIC_KEY},
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

    return templates.TemplateResponse(
        "checkout.html",
        {
            "request": request,
            "order": TEMP_CART_ORDER[order_id],
            "stripe_public_key": STRIPE_PUBLIC_KEY,
        },
    )


@router.post("/request_otp")
async def request_otp(
    request: Request,
    order_id: str = Form(...),
    amount: float = Form(...),
    currency: str = Form(default="vnd"),
    user_id: int = Form(...),
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
    print(f"   amount: {amount}")
    print(f"   currency: {currency}")
    print("="*60)
    
    if not otp_service:
        return {"success": False, "message": "OTP service not available"}

    if not user_id:
        return {"success": False, "message": "Vui lòng đăng nhập để tiếp tục thanh toán"}

    # Tìm user trong database
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"success": False, "message": "Không tìm thấy thông tin người dùng"}

    # Giải mã email
    email = _decrypt_email(user)
    if not email:
        return {"success": False, "message": "Lỗi xử lý thông tin người dùng"}

    # Gửi OTP
    otp = otp_service.send_otp(email, amount, currency, order_id)

    if otp:
        return {
            "success": True,
            "message": f"Mã OTP đã được gửi đến email đã đăng ký. Vui lòng kiểm tra hộp thư.",
            "email_masked": email[:3] + "***@" + email.split("@")[1] if "@" in email else "***",
            "expires_in": 300,  # seconds
        }
    else:
        return {
            "success": False,
            "message": "Không thể gửi OTP. Vui lòng thử lại sau.",
        }


@router.post("/verify_otp")
async def verify_otp(
    request: Request,
    otp: str = Form(...),
    order_id: str = Form(...),
    amount: float = Form(...),
    currency: str = Form(default="vnd"),
    user_id: int = Form(...),
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

    # Lấy user_id từ form data
    if not user_id:
        return JSONResponse(
            status_code=401,
            content={"success": False, "error": "Vui lòng đăng nhập để tiếp tục"},
        )

    # Tìm user trong database
    user = db.query(User).filter(User.id == user_id).first()
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
    nonce: str = Form(...),
    device_fingerprint: str = Form(...),
    otp: str = Form(...),  # OTP code from user - BẮT BUỘC
    user_id: int = Form(None),  # User ID nếu đã login
    db: Session = Depends(get_db),
):
    # Log initial payment request safely (handle missing client)
    client_ip = request.client.host if request.client else None
    logger.info(
        "Payment request received", extra={"order_id": order_id, "ip": client_ip}
    )

    global TEMP_CART_ORDER, CART

    order = next((o for o in MOCK_ORDERS if o["id"] == order_id), None)
    if not order:
        order = TEMP_CART_ORDER.get(order_id)
    if not order:
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": "Order not found"}
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
    # 🔐 OTP VERIFICATION - BẮT BUỘC
    # =========================
    if not otp:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": "❌ Vui lòng nhập mã OTP để xác thực thanh toán!",
            },
        )
    
    # Lấy user_id từ form data
    if not user_id:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": "❌ Vui lòng đăng nhập để tiếp tục thanh toán!",
            },
        )
    
    # Tìm user trong database để lấy email
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": "❌ Không tìm thấy thông tin người dùng!",
            },
        )
    
    # Giải mã email
    email = _decrypt_email(user)
    if not email:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": "❌ Lỗi xử lý thông tin người dùng!",
            },
        )
    
    # Kiểm tra OTP đã được verify chưa (sẽ trả về True nếu đã verify trong 10 phút qua)
    # Không cần verify lại OTP nếu đã verify trước đó
    is_valid = otp_service.verify_otp(email, order_id, otp)
    if not is_valid:
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": "❌ Mã OTP không đúng hoặc đã hết hạn!",
            },
        )

    print(f"✅ OTP verified successfully for {email}")

    order = next((o for o in MOCK_ORDERS if o["id"] == order_id), None)
    if not order:
        order = TEMP_CART_ORDER.get(order_id)
    if not order:
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": "Order not found"}
        )

    # Ensure fraud_result exists even if fraud detector raises
    fraud_result = None

    # =========================
    # 🛡️ FRAUD DETECTION CHECK
    # =========================
    client_ip = request.client.host if request.client else None

    # Lấy user từ form user_id hoặc từ JWT token (ưu tiên form trước)
    user_db = None

    # Cách 1: Lấy từ form user_id (đơn giản nhất)
    if user_id:
        try:
            user_db = (
                db.query(db_models.User).filter(db_models.User.id == user_id).first()
            )
            if user_db:
                print(f"✅ User authenticated from form: id={user_db.id}")
        except Exception as e:
            print(f"⚠️ Error querying user by id: {e}")

    # Cách 2: Fallback - thử lấy từ JWT token nếu không có user_id trong form
    if not user_db:
        try:
            auth = request.headers.get("authorization") or request.headers.get(
                "Authorization"
            )
            if auth and auth.lower().startswith("bearer "):
                token = auth.split()[1]
                try:
                    token_data = verify_access_token(
                        token,
                        HTTPException(
                            status_code=401, detail="could not validate credentials"
                        ),
                    )
                    user_db = (
                        db.query(db_models.User)
                        .filter(db_models.User.id == token_data.id)
                        .first()
                    )
                    if user_db:
                        print(f"✅ User authenticated from JWT: id={user_db.id}")
                except Exception as e:
                    print(f"⚠️ Token verification failed: {e}")
        except Exception as e:
            print(f"⚠️ Error reading Authorization header: {e}")

    if not user_db:
        print("⚠️ User not authenticated - no user_id in form and no valid JWT token")

    try:
        # Lấy thông tin client
        client_ip = request.client.host if request.client else None

        # Lấy user_id để sử dụng trong fraud detection
        fraud_user_id = str(user_db.id) if user_db else str(user_id) if user_id else order_id

        # Tạo transaction input để kiểm tra
        fraud_check = TransactionInput(
            user_id=fraud_user_id,
            amount=(
                float(order["amount"]) / 100
                if order["currency"] == "vnd"
                else float(order["amount"])
            ),  # Convert VND về đơn vị chuẩn
            currency=order["currency"],
            ip_address=client_ip,
            billing_country="VN",  # Có thể lấy từ form hoặc user profile
        )

        # Kiểm tra fraud
        fraud_result = fraud_detector.assess_transaction(fraud_check)

        # Nếu phát hiện fraud, chặn giao dịch
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
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": f"⚠️ Transaction blocked: {fraud_result.message} (Score: {fraud_result.score:.2f})",
                },
            )

    except Exception as e:
        # Log lỗi nhưng vẫn cho phép giao dịch tiếp tục (fail-open mode)
        print(f"⚠️ Fraud detection error: {e}")
        traceback.print_exc()

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
        
        intent = stripe.PaymentIntent.create(
            amount=order["amount"],
            currency=order["currency"],
            description=order["description"],
            payment_method_data={"type": "card", "card": {"token": payment_token}},
            confirm=True,
            return_url="http://127.0.0.1:8000/success_payment",
        )

        if intent.status == "succeeded":
            masked_card = None
            
            try:
                # Get masked card from payment token if possible
                token_data = card_tokenizer.detokenize(payment_token)
                if token_data:
                    masked_card = DataMasking.mask_card_number(
                        token_data.get("card_number", "")
                    )
            except Exception:
                masked_card = "***"

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
