import stripe
from fastapi import HTTPException

ENDPOINT_SECRET = 'whsec_b2f4c0b17936ca5e3673e850c9a7ccaa13996227102099b16b94d2af816ee7bf'

def verify_stripe_signature(payload: bytes, signature: str):
    
    try:
        event = stripe.Webhook.construct_event(
            payload, signature, ENDPOINT_SECRET
        )
        return event
    
    except ValueError as e:
        
        print("Error parsing payload: Invalid JSON.")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationErrir as e:
        
        print("Webhook signature verification failed.")
        raise HTTPException(status_code=400, detail="Invalid signature")
    except Exception as e:
        print(f"Unknown verification error: {str(e)}")
        raise HTTPException(status_code=500, detail = "Internal server error during verification")
    