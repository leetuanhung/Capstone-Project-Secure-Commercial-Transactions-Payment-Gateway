from fastapi import APIRouter, Form, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from dotenv import load_dotenv
import stripe
import os
import time
import json
import traceback
import hashlib
import base64
from backend.config.config import settings
from backend.services.payment_service.security.hsm_client import (
    sign_data,
    generate_secure_random
)
from backend.services.payment_service.security.hsm_client import HSMError
from backend.services.payment_service.security.tokenization import card_tokenizer
from backend.services.payment_service.security.encryption import DataMasking
from backend.services.payment_service.security.fraud_detection import (
    FraudDetector,
    TransactionInput
)
from backend.database.database import get_db
from sqlalchemy.orm import Session
from backend.models import models as db_models
from backend.oauth2.oauth2 import verify_access_token
from backend.services.payment_service.otp_service import init_otp_service, otp_service

# =======================
# CẤU HÌNH & KHỚI TẠO
# =========================
ROOT_DIR = Path(__file__).resolve().parents[3]
load_dotenv(dotenv_path=ROOT_DIR / ".env")

STRIPE_PUBLIC_KEY = settings.Stripe_Public_Key
STRIPE_SECRET_KEY = settings.Stripe_Secret_Key

if not STRIPE_SECRET_KEY:
    raise RuntimeError("STRIPE_SECRET_KEY not configured in .env")

stripe.api_key = STRIPE_SECRET_KEY
templates = Jinja2Templates(directory=str(ROOT_DIR / "frontend" / "templates"))

# =========================
# MOCK DATA (trường hợp test)
# =========================
try:
    from backend.services.order_service.order import MOCK_ORDERS, CART
except Exception:
    MOCK_ORDERS = [
        {"id": "ORD-DEMO-01", "description": "Product A", "amount": 150000, "currency": "vnd"},
        {"id": "ORD-DEMO-02", "description": "Product B", "amount": 300000, "currency": "vnd"},
        {"id": "ORD-FRAUD-TEST", "description": "High Value Test (Will Trigger ML)", "amount": 600000, "currency": "vnd"},  # 6000 VND in DB
    ]
    CART = []

TEMP_CART_ORDER: dict[str, dict] = {}
router = APIRouter(tags=["Payment Service"])

# =========================
# KHỞI TẠO FRAUD DETECTOR & OTP SERVICE
# =========================
fraud_detector = FraudDetector()

# Khởi tạo OTP Service với Redis
try:
    from backend.middleware.rate_limiter import redis_client, USE_REDIS
    if USE_REDIS:
        init_otp_service(redis_client)
        print("✅ OTP Service initialized with Redis")
    else:
        init_otp_service(None)
        print("⚠️ OTP Service initialized (memory-only)")
except Exception as e:
    print(f"⚠️ OTP Service initialization failed: {e}")
    init_otp_service(None)

# =========================
# HÀM KÝ BIÊN LAI BẰNG HSM
# =========================
def create_signed_receipt(transaction_data: dict) -> dict:
    """Ký biên lai thanh toán bằng HSM nếu có; fallback phần mềm nếu HSM không khả dụng."""
    payload = json.dumps(transaction_data, sort_keys=True).encode()
    try:
        signature = sign_data(payload, key_label="DemoKey")   # 🔐 Ký thật bằng HSM
        return {"signed_receipt": signature, "signed_by": "HSM-DemoKey"}
    except (HSMError, Exception):
        # Fallback an toàn: dùng SHA-256 làm dấu vết + random salt (KHÔNG thay thế chữ ký thật)
        salt = os.urandom(16)
        digest = hashlib.sha256(salt + payload).digest()
        soft_sig = base64.b64encode(digest).decode()
        return {"signed_receipt": soft_sig, "signed_by": "SOFTWARE-FALLBACK"}

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
        result = card_tokenizer.generate_token(card_number, cvv, expiry, cardholder_name)
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
async def checkout_single_order(request: Request, order_id: str):
    order = next((o for o in MOCK_ORDERS if o["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    order["currency"] = order.get("currency", "vnd").lower()
    return templates.TemplateResponse(
        "checkout.html",
        {"request": request, "order": order, "stripe_public_key": STRIPE_PUBLIC_KEY},
    )

@router.get("/checkout_cart", response_class=HTMLResponse)
async def checkout_cart(request: Request):
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

    return templates.TemplateResponse("checkout.html", {
        "request": request,
        "order": TEMP_CART_ORDER[order_id],
        "stripe_public_key": STRIPE_PUBLIC_KEY
    })

# =========================
# OTP ENDPOINTS
# =========================
@router.post("/request_otp")
async def request_otp(
    email: str = Form(...),
    order_id: str = Form(...),
    amount: float = Form(...),
    currency: str = Form(default="vnd")
):
    """
    Gửi mã OTP qua Gmail để xác thực thanh toán
    
    Flow:
    1. User nhập email ở checkout page
    2. Click "Gửi mã OTP"
    3. Nhận OTP qua Gmail (6 số)
    4. Nhập OTP và submit payment
    """
    if not otp_service:
        return {"success": False, "message": "OTP service not available"}
    
    otp = otp_service.send_otp(email, amount, currency, order_id)
    
    if otp:
        return {
            "success": True,
            "message": f"Mã OTP đã được gửi đến {email}. Vui lòng kiểm tra hộp thư.",
            "expires_in": 300  # seconds
        }
    else:
        return {
            "success": False,
            "message": "Không thể gửi OTP. Vui lòng kiểm tra email hoặc thử lại sau."
        }

# =========================
# XỬ LÝ THANH TOÁN
# =========================
@router.post("/create_payment")
async def create_payment(request: Request,
                         payment_token: str = Form(...),
                         order_id: str = Form(...),
                         nonce: str = Form(...),
                         device_fingerprint: str = Form(...),
                         email: str = Form(None),  # Email for OTP
                         otp: str = Form(None),    # OTP code from user
                         user_id: int = Form(None),  # User ID nếu đã login
                         db: Session = Depends(get_db)):
    global TEMP_CART_ORDER, CART
    
    # =========================
    # 🛡️ NONCE VALIDATION - Chống replay attack
    # =========================
    try:
        from backend.middleware.rate_limiter import redis_client, USE_REDIS
        
        if USE_REDIS:
            nonce_key = f"nonce:{nonce}"
            # Check if nonce already exists
            if redis_client.exists(nonce_key):
                return templates.TemplateResponse("error.html", {
                    "request": request,
                    "error": "⚠️ Invalid request: This transaction has already been processed (duplicate nonce)"
                })
            
            # Store nonce with 24h expiry
            redis_client.setex(nonce_key, 86400, "used")
            print(f"✅ Nonce validated and stored: {nonce[:8]}...")
        else:
            print("⚠️ Nonce validation skipped - Redis unavailable")
    except Exception as e:
        print(f"⚠️ Nonce validation error: {e}")
        # Continue with payment (fail-open) but log the issue
    
    # =========================
    # 🔐 OTP VERIFICATION (nếu có email và OTP)
    # =========================
    if email and otp:
        if otp_service and not otp_service.verify_otp(email, order_id, otp):
            return templates.TemplateResponse("error.html", {
                "request": request,
                "error": "❌ Mã OTP không đúng hoặc đã hết hạn. Vui lòng thử lại."
            })
        print(f"✅ OTP verified for {email}")
    
    order = next((o for o in MOCK_ORDERS if o["id"] == order_id), None)
    if not order:
        order = TEMP_CART_ORDER.get(order_id)
    if not order:
        return templates.TemplateResponse("error.html", {"request": request, "error": "Order not found"})

    # =========================
    # 🛡️ FRAUD DETECTION CHECK
    # =========================
    # Lấy thông tin client
    client_ip = request.client.host if request.client else None

    # Lấy user từ form user_id hoặc từ JWT token (ưu tiên form trước)
    user_db = None
    
    # Cách 1: Lấy từ form user_id (đơn giản nhất)
    if user_id:
        try:
            user_db = db.query(db_models.User).filter(db_models.User.id == user_id).first()
            if user_db:
                print(f"✅ User authenticated from form: id={user_db.id}")
        except Exception as e:
            print(f"⚠️ Error querying user by id: {e}")
    
    # Cách 2: Fallback - thử lấy từ JWT token nếu không có user_id trong form
    if not user_db:
        try:
            auth = request.headers.get("authorization") or request.headers.get("Authorization")
            if auth and auth.lower().startswith("bearer "):
                token = auth.split()[1]
                try:
                    token_data = verify_access_token(token, HTTPException(status_code=401, detail="could not validate credentials"))
                    user_db = db.query(db_models.User).filter(db_models.User.id == token_data.id).first()
                    if user_db:
                        print(f"✅ User authenticated from JWT: id={user_db.id}")
                except Exception as e:
                    print(f"⚠️ Token verification failed: {e}")
        except Exception as e:
            print(f"⚠️ Error reading Authorization header: {e}")
    
    if not user_db:
        print("⚠️ User not authenticated - no user_id in form and no valid JWT token")

    try:
        # Tạo transaction input để kiểm tra; nếu có user, truyền user id để ML lấy lịch sử
        fraud_check = TransactionInput(
            user_id=str(user_db.id) if user_db else order_id,
            amount=float(order["amount"]) / 100 if order["currency"] == "vnd" else float(order["amount"]),
            currency=order["currency"],
            ip_address=client_ip,
            billing_country="VN"
        )

        # Kiểm tra fraud
        fraud_result = fraud_detector.assess_transaction(fraud_check)

        # Nếu phát hiện fraud, chặn giao dịch
        if fraud_result.is_fraud:
            return templates.TemplateResponse("error.html", {
                "request": request,
                "error": f"⚠️ Transaction blocked: {fraud_result.message} (Score: {fraud_result.score:.2f})"
            })

    except Exception as e:
        # Log lỗi nhưng vẫn cho phép giao dịch tiếp tục (fail-open mode)
        print(f"⚠️ Fraud detection error: {e}")
        traceback.print_exc()

    # =========================
    # XỬ LÝ THANH TOÁN VỚI STRIPE
    # =========================
    try:
        intent = stripe.PaymentIntent.create(
            amount=order["amount"],
            currency=order["currency"],
            description=order["description"],
            payment_method_data={
                "type": "card",
                "card": {"token": payment_token}
            },
            confirm=True,
            return_url="http://127.0.0.1:8000/success_payment"
        )

        if intent.status == "succeeded":
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
                "nonce": nonce_value
            }

            # ✅ Ký biên lai bằng HSM
            signed_receipt = create_signed_receipt(receipt_data)

            # Lưu lịch sử đơn hàng vào DB nếu có user đăng nhập
            try:
                converted_amount = float(order["amount"]) / 100 if order["currency"] == "vnd" else float(order["amount"])
                if db is not None and user_db:
                    new_order = db_models.Order(owner_id=user_db.id, status="SUCCESS", total_price=converted_amount)
                    db.add(new_order)
                    db.commit()
                    db.refresh(new_order)
                    print(f"✅ Order saved to DB: id={new_order.id} owner={user_db.id} total={converted_amount}")
                else:
                    print("⚠️ User not authenticated - skipping DB order persistence")
            except Exception as e:
                print(f"⚠️ Error saving order to DB: {e}")
                try:
                    db.rollback()
                except Exception:
                    pass

            if order_id.startswith("CART-"):
                del TEMP_CART_ORDER[order_id]
                CART.clear()

            return templates.TemplateResponse("success.html", {
                "request": request,
                "receipt": receipt_data,
                "order": order,
                "signed_receipt": signed_receipt
            })

        else:
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error": f"Payment requires confirmation. Status: {intent.status}"}
            )

    except stripe.error.CardError as e:
        body = e.json_body
        err = body.get('error', {})
        return templates.TemplateResponse("error.html", {"request": request, "error": f"Payment failed: {err.get('message')}"})

    except Exception as e:
        traceback.print_exc()
        return templates.TemplateResponse("error.html", {"request": request, "error": f"Error processing payment: {e}"})
