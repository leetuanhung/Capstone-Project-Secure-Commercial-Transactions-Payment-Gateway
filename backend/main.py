from fastapi import FastAPI, Form, Request, HTTPException, Header, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
import os
import json
from pathlib import Path
import stripe
from dotenv import load_dotenv
from fastapi.staticfiles import StaticFiles
from backend.database.database import engine
from backend.models import models
from backend.services.payment_service import payment
from backend.services.order_service import order
from backend.services.user_service import user
from backend.config.config import settings
from backend.middleware.request_id import RequestIDMiddleware
from backend.middleware.rate_limiter import RateLimitMiddleware
from backend.middleware.hmac_verifier import HMACVerifierMiddleware
from backend.middleware.cors import setup_cors
from sqlalchemy import text
import logging

from backend.utils.logger import (
    init_logging,
    get_application_logger,
    log_security_event,
    log_payment_attempt
)
from backend.webhooks.handler import dispatch_event
from backend.webhooks.signature_verify import verify_stripe_signature

# Initialize logging khi app start
init_logging()

# Get logger
logger = get_application_logger(__name__)

# Log khi app khởi động
logger.info("Payment System starting...")
logger.info(f"Environment: {os.getenv('ENVIRONMENT', 'development')}")

load_dotenv()
models.Base.metadata.create_all(bind=engine)


def _ensure_user_security_columns() -> None:
    """Ensure encrypted columns exist for user registration security."""
    statements = (
        "ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS name_encrypted TEXT",
        "ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS email_encrypted TEXT",
        "ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS phone_encrypted TEXT",
    )
    with engine.begin() as connection:
        for stmt in statements:
            connection.execute(text(stmt))


_ensure_user_security_columns()
user.ensure_user_security_setup()


def _initialize_security_components() -> None:
    """Attempt to import and initialize payment/security modules so any
    environment or dependency problems are discovered at startup.

    This is safe to call multiple times and only prints warnings if parts
    of the security stack (HSM bindings, extra packages) are missing.
    """
    try:
        # Field encryption, data masking and tokenization are imported for
        # their module-level initialization (singletons, key loading).
        from backend.services.payment_service.security import encryption as _enc
        from backend.services.payment_service.security import tokenization as _tok
        # hsm_client may warn if PKCS#11 is not available; import to surface
        # that information early in the startup logs.
        from backend.services.payment_service.security import hsm_client as _hsm
        print("Security modules loaded: encryption, tokenization, hsm_client")
    except Exception as exc:  # pragma: no cover - defensive startup logging
        print("Warning: some security components failed to initialize:", str(exc))


_initialize_security_components()

app = FastAPI()

# Setup middleware: CORS, Request-ID, rate limiting and HMAC verifier
setup_cors(app)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(HMACVerifierMiddleware)

# Include routers

app.include_router(user.router, prefix="/auth")
app.include_router(payment.router, prefix="/payment")
# Also expose payment service under /payment_service for templates referencing that path
app.include_router(payment.router, prefix="/payment_service")
app.include_router(order.router, prefix="/order_service")

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend" / "templates"))

# Serve static files (css, images, js) from /static
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend" / "static")), name="static")

STRIPE_PUBLIC_KEY = settings.Stripe_Public_Key
STRIPE_SECRET_KEY = settings.Stripe_Secret_Key

if not STRIPE_PUBLIC_KEY or not STRIPE_SECRET_KEY:
    raise ValueError("Error: STRIPE_PUBLIC_KEY and STRIPE_SECRET_KEY must be set in .env")

stripe.api_key = STRIPE_SECRET_KEY

USERS_FILE = Path(__file__).resolve().parent / "users.json"

def load_users():
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            print("WARNING: users.json corrupted.")
    return {"admin": "123456", "phuc": "password"}

def save_users(users):
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

fake_users = load_users()

# Notes:
# - order_service and payment_service provide their own MOCK_ORDERS, CART and payment handlers.
# - To avoid duplicate state and routing, main.py delegates store/order/payment pages to the services.

@app.post("/webhook")
async def webhook_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    stripe_signature: str = Header(...)
):
    payload = await request.body()
    try:
        event = verify_stripe_signature(payload, stripe_signature)
    except HTTPException as he:
        # verification failed (signature/parse error) -> return that HTTP error
        raise he
    except Exception as e:
        # unexpected error during verification
        logger.error("Webhook verification error", exc_info=True)
        raise HTTPException(status_code=500, detail="Webhook verification failed")

    # enqueue handler
    background_tasks.add_task(dispatch_event, event)
    return {"status": "received", "message": "Event added to background queue"}

@app.post("/debug-webhook")
async def debug_webhook(request: Request, background_tasks: BackgroundTasks, stripe_signature: str = Header(None)):
    """
    Debug endpoint: trả về headers + preview body để kiểm tra connectivity từ Stripe CLI
    Không thực hiện verify/signature — chỉ dùng để xác định lỗi mạng hoặc crash.
    """
    body = await request.body()
    headers = dict(request.headers)
    logger.info("Debug webhook received", extra={"received_headers": list(headers.keys()), "preview": (body[:200].decode(errors='ignore'))})
    return {"status": "ok", "received_headers": list(headers.keys()), "body_preview": (body[:200].decode(errors='ignore'))}

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, message: Optional[str] = None):
    return templates.TemplateResponse("login.html", {"request": request, "message": message})


@app.get("/store")
async def store_redirect():
    """Redirect /store to the order service storefront to keep a single source of truth."""
    return RedirectResponse(url="/order_service/orders", status_code=302)


@app.get("/orders")
async def redirect_orders_root():
    """Backward-compatible redirect: /orders -> /order_service/orders"""
    return RedirectResponse(url="/order_service/orders", status_code=302)


@app.get("/orders/orders")
async def redirect_orders():
    """Backward-compatible redirect: /orders/orders -> /order_service/orders"""
    return RedirectResponse(url="/order_service/orders", status_code=302)

# Debug routes
@app.on_event("startup")
async def startup_event():
    print("=== REGISTERED ROUTES ===")
    for route in app.routes:
        if hasattr(route, "methods") and hasattr(route, "path"):
            print(f"{list(route.methods)} {route.path}")