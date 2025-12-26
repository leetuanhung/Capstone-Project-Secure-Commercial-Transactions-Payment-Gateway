import stripe
import os
from fastapi import HTTPException
from backend.utils.logger import get_error_logger

ENDPOINT_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')
logger = get_error_logger()

# Nếu secret chưa cấu hình, log rõ ràng để tránh lỗi khó debug (Stripe signature verify sẽ fail/raise)
if not ENDPOINT_SECRET:
    logger.error("STRIPE_WEBHOOK_SECRET is not set; webhook signature verification will fail.")
    # Đây là lỗi cấu hình — trả HTTP 500 khi verify được gọi
    # (không raise khi import để vẫn cho phép chạy app; verify_stripe_signature sẽ raise khi được gọi)

def verify_stripe_signature(payload: bytes, signature: str):
    if not ENDPOINT_SECRET:
        logger.error("Attempt to verify webhook but STRIPE_WEBHOOK_SECRET not configured")
        raise HTTPException(status_code=500, detail="Webhook signing secret not configured")

    try:
        event = stripe.Webhook.construct_event(
            payload, signature, ENDPOINT_SECRET
        )
        return event

    except ValueError as e:
        logger.error("Webhook payload invalid", exc_info=True)
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        logger.error("Webhook signature verification failed", exc_info=True)
        raise HTTPException(status_code=400, detail="Invalid signature")
    except Exception as e:
        logger.error(f"Unknown verification error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during verification")
