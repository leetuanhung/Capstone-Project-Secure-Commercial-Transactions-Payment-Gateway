import hmac
import secrets
from typing import Optional

from fastapi import HTTPException, Request, status
from starlette.responses import Response


CSRF_COOKIE_NAME = "csrf_token"
CSRF_FORM_FIELD = "csrf_token"


def is_https_request(request: Request) -> bool:
    forwarded_proto = (request.headers.get("x-forwarded-proto") or "").lower()
    if forwarded_proto:
        return forwarded_proto == "https"
    return request.url.scheme == "https"


def generate_csrf_token() -> str:
    # 32 bytes of entropy -> urlsafe string
    return secrets.token_urlsafe(32)


def get_csrf_cookie(request: Request) -> Optional[str]:
    token = request.cookies.get(CSRF_COOKIE_NAME)
    return token if token else None


def ensure_csrf_token(request: Request) -> str:
    return get_csrf_cookie(request) or generate_csrf_token()


def set_csrf_cookie(response: Response, request: Request, token: str) -> None:
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        httponly=False,
        secure=is_https_request(request),
        samesite="lax",
        path="/",
    )


def validate_csrf(request: Request, submitted_token: str) -> None:
    cookie_token = get_csrf_cookie(request)

    if not cookie_token or not submitted_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed",
        )

    if not hmac.compare_digest(cookie_token, submitted_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed",
        )
