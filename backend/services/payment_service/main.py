import secrets
from passlib.context import CryptContext
import os
from dotenv import load_dotenv
import stripe

load_dotenv()

stripe.api_key = os.getenv('STRIPE_API_KEY')

def create_signed_receipt_mock(transaction_data: dict) -> dict:
    """Giả lập việc tạo và ký một biên lai giao dịch"""
    jws_signature_mock = f"HEADER.PAYLOAD_{secrets.token_hex(16).upper()}.SIGNATURE_{secrets.token_hex(32).upper()}"
    return {"signed_receipt": jws_signature_mock, "signed_by": "MockHSM-KeyID-12345"}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash(password: str):
    password_str = str(password)[:72]
    return pwd_context.hash(password_str)

def verify(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)