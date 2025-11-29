# backend/gateway/middleware/rate_limiter.py
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, status
from fastapi.responses import JSONResponse
import time
import redis
import os
from dotenv import load_dotenv
from backend.utils.logger import log_security_event
load_dotenv()

# Giới hạn: 60 requests / 60 giây mỗi IP
RATE_LIMIT = 60
WINDOW = 60

# Initialize Redis client
try:
    redis_client = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        db=int(os.getenv("REDIS_DB", 0)),
        decode_responses=True,
        socket_connect_timeout=2,
    )
    redis_client.ping()  # Test connection
    print("✅ Rate limiter connected to Redis")
    USE_REDIS = True
except (redis.ConnectionError, Exception) as e:
    print(f"⚠️ Redis unavailable for rate limiter, falling back to in-memory cache: {e}")
    USE_REDIS = False
    cache = {}  # Fallback to in-memory cache


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    ✅ Giới hạn tần suất request (anti-DoS) với Redis.
    Fallback to in-memory nếu Redis không khả dụng.
    """

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host
        now = int(time.time())

        if USE_REDIS:
            # Redis-based rate limiting with sliding window
            key = f"rate_limit:{ip}"
            pipe = redis_client.pipeline()

            # Remove old timestamps outside window
            pipe.zremrangebyscore(key, 0, now - WINDOW)
            # Count current requests in window
            pipe.zcard(key)
            # Add current timestamp
            pipe.zadd(key, {str(now): now})
            # Set expiry
            pipe.expire(key, WINDOW)

            results = pipe.execute()
            request_count = results[1]  # zcard result

            if request_count >= RATE_LIMIT:
                return JSONResponse(
                    {"detail": "Too many requests. Try again later."},
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                )
        else:
            # Fallback: in-memory rate limiting
            cache.setdefault(ip, [])
            cache[ip] = [t for t in cache[ip] if now - t < WINDOW]

            if len(cache[ip]) >= RATE_LIMIT:
                
                log_security_event(
                    event_type="rate_limit_exceeded",
                    severity="warning",
                    ip_address=ip,
                    details={"count": len(cache[ip]), "limit": RATE_LIMIT},
                )
                
                return JSONResponse(
                    {"detail": "Too many requests. Try again later."},
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            cache[ip].append(now)

        return await call_next(request)
