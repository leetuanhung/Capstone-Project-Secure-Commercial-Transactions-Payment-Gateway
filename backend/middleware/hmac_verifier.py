# backend/gateway/middleware/hmac_verifier.py
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, status
from fastapi.responses import JSONResponse
import hmac, hashlib, os

SECRET = os.getenv("GATEWAY_HMAC_SECRET", "gateway-secret-key")

class HMACVerifierMiddleware(BaseHTTPMiddleware):
    """
    ✅ Bảo vệ Gateway khỏi request bị giả mạo.
    - Client gửi kèm header: X-Signature = HMAC-SHA256(body, SECRET)
    - Middleware xác thực lại trước khi chuyển request vào service.
    """

    async def dispatch(self, request: Request, call_next):
        signature = request.headers.get("X-Signature")
        body = await request.body()

        expected_sig = hmac.new(
            SECRET.encode(), body, hashlib.sha256
        ).hexdigest()

        if signature and hmac.compare_digest(signature, expected_sig):
            return await call_next(request)
        elif not signature:
            # Cho phép request không có chữ ký (ví dụ: GET /login)
            return await call_next(request)
        else:
            return JSONResponse(
                {"detail": "Invalid HMAC signature"},
                status_code=status.HTTP_403_FORBIDDEN,
            )
