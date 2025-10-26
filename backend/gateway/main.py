# /backend/gateway/main.py
import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

# === Trỏ tới ROOT PROJECT (chứa cả backend/ và frontend/) ===
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(BASE_DIR))  # cho phép import backend.*

# === Import router từ các service (tuyệt đối) ===
from backend.services.user_service.user import router as user_router
from backend.services.order_service.order import router as order_router
from backend.services.payment_service.payment import router as payment_router
from backend.gateway.middleware.auth import AuthMiddleware
from backend.gateway.middleware.rate_limiter import RateLimitMiddleware
from backend.gateway.middleware.request_id import RequestIDMiddleware
from backend.gateway.middleware.hmac_verifier import HMACVerifierMiddleware
from backend.gateway.middleware.cors import setup_cors

app = FastAPI(title="API Gateway (Unified Docs)")

# Templates: ROOT/frontend/templates
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend" / "templates"))

# Mount static files (CSS, Images, JS)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend" / "static")), name="static")

app.add_middleware(RequestIDMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(HMACVerifierMiddleware)
app.add_middleware(AuthMiddleware)
setup_cors(app)
# Gắn routers với prefix
app.include_router(user_router, prefix="/user_service", tags=["User Service"])
app.include_router(order_router, prefix="/order_service", tags=["Order Service"])
app.include_router(payment_router, prefix="/payment_service", tags=["Payment Service"])

@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url="/user_service/login", status_code=303)
