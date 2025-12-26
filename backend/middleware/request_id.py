# backend/gateway/middleware/request_id.py
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
import uuid

from backend.utils.logger import set_request_context, clear_request_context

class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    ✅ Gắn một Request-ID duy nhất cho mỗi request để phục vụ tracing/logging.
    """

    async def dispatch(self, request: Request, call_next):
        req_id = str(uuid.uuid4())
        request.state.request_id = req_id
        user_id = request.cookies.get("user_id")
        ip_address = request.client.host if request.client else None

        tokens = set_request_context(
            request_id=req_id,
            user_id=user_id,
            ip_address=ip_address,
        )
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = req_id
            return response
        finally:
            clear_request_context(tokens)
