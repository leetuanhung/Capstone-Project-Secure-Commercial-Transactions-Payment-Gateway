import json
from typing import Iterable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import HTMLResponse, JSONResponse, Response
from fastapi import Request

from backend.utils import csrf


class CSRFMiddleware(BaseHTTPMiddleware):
    """Global CSRF protection.

    Enforces CSRF for unsafe HTTP methods (POST/PUT/PATCH/DELETE).

    Token sources (first match wins):
    - Header: X-CSRF-Token / X-XSRF-Token
    - Form field: csrf_token (multipart or urlencoded)
    - JSON body key: csrf_token

    Uses double-submit cookie pattern:
    - Cookie name: csrf_token
    - Submitted token must match cookie value

    Webhooks and other machine-to-machine endpoints should be exempted.
    """

    def __init__(
        self,
        app,
        exempt_paths: Optional[Iterable[str]] = None,
        exempt_prefixes: Optional[Iterable[str]] = None,
    ):
        super().__init__(app)
        self._exempt_paths = set(exempt_paths or [])
        self._exempt_prefixes = tuple(exempt_prefixes or [])

    def _is_exempt(self, path: str) -> bool:
        if path in self._exempt_paths:
            return True
        return any(path.startswith(prefix) for prefix in self._exempt_prefixes)

    async def _get_submitted_token(self, request: Request) -> Optional[str]:
        # Priority: check header first (doesn't consume body)
        header_token = request.headers.get("x-csrf-token") or request.headers.get("x-xsrf-token")
        if header_token:
            return header_token

        # For JSON: read body but DON'T consume it (FastAPI will re-read)
        content_type = (request.headers.get("content-type") or "").lower()
        if content_type.startswith("application/json"):
            try:
                body = await request.body()
                if not body:
                    return None
                payload = json.loads(body.decode("utf-8"))
                if isinstance(payload, dict):
                    token = payload.get(csrf.CSRF_FORM_FIELD)
                    return token if isinstance(token, str) else None
            except Exception:
                return None

        # For form submissions (urlencoded or multipart), accept csrf_token field.
        # Starlette caches the request body internally, so reading form here won't
        # prevent endpoints from reading it again.
        if (
            content_type.startswith("application/x-www-form-urlencoded")
            or content_type.startswith("multipart/form-data")
        ):
            try:
                form = await request.form()
                token = form.get(csrf.CSRF_FORM_FIELD)
                return token if isinstance(token, str) else None
            except Exception:
                return None

        return None

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Ensure CSRF cookie exists for safe methods
        if request.method in ("GET", "HEAD", "OPTIONS"):
            response: Response = await call_next(request)
            if not csrf.get_csrf_cookie(request):
                token = csrf.generate_csrf_token()
                csrf.set_csrf_cookie(response, request, token)
            return response

        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if self._is_exempt(path):
                return await call_next(request)

            submitted = await self._get_submitted_token(request)
            try:
                csrf.validate_csrf(request, submitted or "")
            except Exception:
                accept = (request.headers.get("accept") or "").lower()
                if "text/html" in accept:
                    return HTMLResponse(
                        "CSRF validation failed",
                        status_code=403,
                        headers={"Cache-Control": "no-store"},
                    )
                return JSONResponse(
                    {"detail": "CSRF validation failed"},
                    status_code=403,
                    headers={"Cache-Control": "no-store"},
                )

        return await call_next(request)
