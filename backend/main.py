from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
import os
import secrets
import time
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

load_dotenv()
models.Base.metadata.create_all(bind=engine)

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