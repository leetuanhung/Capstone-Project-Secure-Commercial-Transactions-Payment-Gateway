from fastapi import status, HTTPException, Depends, APIRouter
from sqlalchemy.orm import Session
from backend.database.database import get_db
from backend.schemas import order
from backend.utils import utils
from backend.models import models
from backend.oauth2 import oauth2   
from typing import List
from pydantic import BaseModel, Field
from typing import Optional


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