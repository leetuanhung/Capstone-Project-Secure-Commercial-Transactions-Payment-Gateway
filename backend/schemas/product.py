from statistics import quantiles
from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional
from enum import Enum
from backend.database.database import Base
from pydantic import BaseModel, EmailStr, ConfigDict, Field

class ProductCreate(BaseModel):
    name: str
    price: float
    quantity: int
    
class ProductResponse(BaseModel):
    id: int
    name: str
    price: float
    quantity: int
    created_at: datetime
    
    class Config:
        from_attributes = True
    