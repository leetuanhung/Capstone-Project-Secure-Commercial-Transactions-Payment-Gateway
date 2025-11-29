import stripe
import os
from fastapi import HTTPException
from backend.utils.logger import get_error_logger
ENDPOINT_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')
logger = get_error_logger()
def verify_stripe_signature(payload: bytes, signature: str):
    
    try:
        event = stripe.Webhook.construct_event(
            payload, signature, ENDPOINT_SECRET
        )
        return event
    
    except ValueError as e:
        
        logger.error("Webhook payload invalid", exc_info=True)
        print("Error parsing payload: Invalid JSON.")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationErrir as e:
        
        logger.error("Webhook signature verification failed", exc_info=True)
        print("Webhook signature verification failed.")
        raise HTTPException(status_code=400, detail="Invalid signature")
    except Exception as e:
        print(f"Unknown verification error: {str(e)}")
        raise HTTPException(status_code=500, detail = "Internal server error during verification")
    