# backend/gateway/middleware/request_id.py
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
import uuid

class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    ✅ Gắn một Request-ID duy nhất cho mỗi request để phục vụ tracing/logging.
    """

    async def dispatch(self, request: Request, call_next):
        req_id = str(uuid.uuid4())
        request.state.request_id = req_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = req_id
        return response
