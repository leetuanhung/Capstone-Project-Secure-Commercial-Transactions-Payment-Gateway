from fastapi import status, HTTPException, Depends, APIRouter
from sqlalchemy.orm import Session
from backend.database.database import get_db
from backend.schemas import order
from backend.utils import utils
from backend.models import models
from backend.oauth2 import oauth2   
from typing import List
from pydantic import BaseModel, Field, validator
from typing import Optional
import re


class PaymentCreateRequest(BaseModel):
    """Validated payment creation request for /create_payment endpoint"""
    payment_token: str = Field(..., min_length=20, max_length=200, description="Stripe token từ Hosted Fields")
    order_id: str = Field(..., min_length=5, max_length=100, pattern=r'^[A-Za-z0-9_-]+$', description="Order ID")
    nonce: str = Field(..., min_length=16, max_length=64, pattern=r'^[A-Za-z0-9_-]+$', description="Nonce chống replay attack")
    device_fingerprint: str = Field(..., min_length=10, max_length=500, description="Device fingerprint")
    
    @validator('payment_token')
    def validate_token_format(cls, v):
        if not v.startswith('tok_'):
            raise ValueError('payment_token phải bắt đầu bằng tok_')
        return v
    
    @validator('nonce')
    def validate_nonce_format(cls, v):
        # UUID format or crypto random
        if not re.match(r'^[a-zA-Z0-9_-]{16,64}$', v):
            raise ValueError('nonce format không hợp lệ')
        return v


class CreatePaymentIntentRequest(BaseModel):
    amount: int = Field(..., gt=0, description="Số tiền (cents)")
    currency: str = Field(default="usd")
    description: Optional[str] = None
    receipt_email: Optional[str] = None
    idempotency_key: Optional[str] = None
    
class RefundRequest(BaseModel):
    payment_intent_id: Optional[str] = None
    charge_id: Optional[str] = None
    amount: Optional[int] = None
    reason: Optional[str] = None
    idempotency_key: Optional[str] = None