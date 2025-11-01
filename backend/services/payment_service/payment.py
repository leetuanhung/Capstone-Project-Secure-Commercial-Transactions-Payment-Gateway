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
from backend.config.config import settings
from backend.services.payment_service.security.hsm_client import (
    sign_data,
    generate_secure_random
)

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
# HÀM KÝ BIÊN LAI BẰNG HSM
# =========================
def create_signed_receipt(transaction_data: dict) -> dict:
    """Ký biên lai thanh toán bằng khóa RSA trong HSM"""
    payload = json.dumps(transaction_data).encode()
    signature = sign_data(payload, key_label="DemoKey")   # 🔐 Ký thật bằng HSM
    return {
        "signed_receipt": signature,
        "signed_by": "HSM-DemoKey"
    }

# =========================
# API ROUTES
# =========================
@router.get("/healthz")
async def health_check():
    return {"status": "ok", "service": "payment_service"}

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
    global TEMP_CART_ORDER, CART

    order = next((o for o in MOCK_ORDERS if o["id"] == order_id), None)
    if not order:
        order = TEMP_CART_ORDER.get(order_id)
    if not order:
        return templates.TemplateResponse("error.html", {"request": request, "error": "Order not found"})

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

            # ✅ Tạo nonce an toàn từ HSM
            nonce_value = generate_secure_random(12)

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
