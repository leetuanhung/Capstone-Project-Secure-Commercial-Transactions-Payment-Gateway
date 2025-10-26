from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional
from enum import Enum
from backend.database.database import Base
from pydantic import BaseModel, EmailStr, ConfigDict, Field


class PaymentStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"
    
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = None
    
class UserResponse(BaseModel):
    id: int
    email: EmailStr
    name: str
    phone: Optional[str] = None
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class UserProfile(BaseModel):
    id: int
    email: EmailStr
    name: str
    phone: Optional[str] = None
    total_orders: int = 0
    total_spent: float = 0.0
    
