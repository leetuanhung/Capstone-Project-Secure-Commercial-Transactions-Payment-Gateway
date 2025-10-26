# backend/gateway/middleware/auth.py
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, status
from fastapi.responses import JSONResponse
from backend.oauth2 import oauth2

class AuthMiddleware(BaseHTTPMiddleware):
    """
    ✅ Middleware xác thực JWT cho mọi request đi qua API Gateway.
    - Kiểm tra token trong Header Authorization: Bearer <token>
    - Giải mã JWT và gán thông tin user_id vào request.state
    - Nếu không có token → bỏ qua (để public route vẫn chạy)
    """

    async def dispatch(self, request: Request, call_next):
        auth_header = request.headers.get("Authorization")

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            payload = oauth2.verify_access_token(token)
            if not payload:
                return JSONResponse(
                    {"detail": "Invalid or expired token"},
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            # Gắn user_id vào request.state để service bên dưới dùng
            request.state.user_id = payload.get("user_id")
        else:
            request.state.user_id = None  # public route

        return await call_next(request)
