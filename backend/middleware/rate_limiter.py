# backend/gateway/middleware/rate_limiter.py
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, status
from fastapi.responses import JSONResponse
import time

# Giới hạn: 30 requests / 60 giây mỗi IP
RATE_LIMIT = 1
WINDOW = 60
cache = {}  # {ip: [timestamps]}

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    ✅ Giới hạn tần suất request (anti-DoS).
    """

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host
        now = time.time()
        cache.setdefault(ip, [])
        cache[ip] = [t for t in cache[ip] if now - t < WINDOW]

        if len(cache[ip]) >= RATE_LIMIT:
            return JSONResponse(
                {"detail": "Too many requests. Try again later."},
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        cache[ip].append(now)
        return await call_next(request)
