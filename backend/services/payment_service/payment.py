from fastapi import APIRouter, Form, Request, HTTPException
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

from backend.utils.logger import (
    get_application_logger,
    log_payment_attempt,
    log_security_event,
    get_error_logger
)

logger = get_application_logger(__name__)

# =========================
# CẤU HÌNH & KHỞI TẠO
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
    ]
    CART = []

TEMP_CART_ORDER: dict[str, dict] = {}
router = APIRouter(tags=["Payment Service"])

# =========================
# KHỞI TẠO FRAUD DETECTOR
# =========================
fraud_detector = FraudDetector()

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
# XỬ LÝ THANH TOÁN
# =========================
@router.post("/create_payment")
async def create_payment(request: Request,
                         payment_token: str = Form(...),
                         order_id: str = Form(...),
                         nonce: str = Form(...),
                         device_fingerprint: str = Form(...)):
    logger.info(
        extra={
            'order_id': order_id,
            'amount': order["amount"],
            'currency': order["currency"]
        }
    )
    global TEMP_CART_ORDER, CART

    order = next((o for o in MOCK_ORDERS if o["id"] == order_id), None)
    if not order:
        order = TEMP_CART_ORDER.get(order_id)
    if not order:
        return templates.TemplateResponse("error.html", {"request": request, "error": "Order not found"})

    # =========================
    # 🛡️ FRAUD DETECTION CHECK
    # =========================
    try:
        # Lấy thông tin client
        client_ip = request.client.host if request.client else None
        
        # Tạo transaction input để kiểm tra
        fraud_check = TransactionInput(
            user_id=order_id,  # Có thể thay bằng user_id thật từ session/JWT
            amount=float(order["amount"]) / 100 if order["currency"] == "vnd" else float(order["amount"]),  # Convert VND về đơn vị chuẩn
            currency=order["currency"],
            ip_address=client_ip,
            billing_country="VN"  # Có thể lấy từ form hoặc user profile
        )
        
        # Kiểm tra fraud
        fraud_result = fraud_detector.assess_transaction(fraud_check)
        
        # Nếu phát hiện fraud, chặn giao dịch
        if fraud_result.is_fraud:
            log_security_event(
                event_type='fraud_blocked',
                severity='critical',
                user_id=order_id,
                ip_address=request.client.host,
                details={
                    'fraud_score': fraud_result.score,
                    'rules': fraud_result.triggered_rules
                }
            )
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
            log_payment_attempt(
                transaction_id=intent.id,
                order_id=order_id,
                amount=order["amount"]/100,
                currency=order["currency"],  
                status="success",         
                fraud_score=fraud_result.score,
                ip_address=request.client.host, 
                device_fingerprint=device_fingerprint,  
                payment_method="card" 
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
                "nonce": nonce_value
            }

            # ✅ Ký biên lai bằng HSM
            signed_receipt = create_signed_receipt(receipt_data)

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
            
            logger.warning(f"Payment incomplete: {intent.status}", extra={'order id': order_id})

            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error": f"Payment requires confirmation. Status: {intent.status}"}
            )            

    except stripe.CardError as e:
        body = e.json_body
        err = body.get('error', {})
        logger.error(
        "Card declined by Stripe",
        extra={
            'order_id': order_id,
            'error_code': err.get('code'),
            'error_message': err.get('message'),
            'decline_code': err.get('decline_code'),
            'ip_address': request.client.host
        }
    )
        return templates.TemplateResponse("error.html", {"request": request, "error": f"Payment failed: {err.get('message')}"})

    except stripe.InvalidRequestError as e:
        # Ghi log lỗi request (như lỗi URL vừa rồi) vào file errors.log
        logger.error(f"Stripe Invalid Request: {e}", exc_info=True, extra={'order_id': order_id})
        return templates.TemplateResponse("error.html", {"request": request, "error": f"Invalid Data: {e}"})

    except Exception as e:
        logger.error(
        "Critical error in payment processing",
        exc_info=True,
        extra={
            'order_id': order_id,
            'ip_address': request.client.host,
            'error_type': type(e).__name__
        }
    )
        return templates.TemplateResponse("error.html", {"request": request, "error": f"Error processing payment: {e}"})
