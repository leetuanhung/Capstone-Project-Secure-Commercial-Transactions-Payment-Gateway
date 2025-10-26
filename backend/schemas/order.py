from pydantic import BaseModel
from typing import List, Optional

class ProductBase(BaseModel):
    name: str
    description: Optional[str]
    price: float
    quantity: int
    image_url: Optional[str]

class OrderItemCreate(BaseModel):
    product_id: int
    quantity: int = 1

class OrderCreate(BaseModel):
    user_id: int
    items: List[OrderItemCreate]

class OrderItemResponse(BaseModel):
    product_id: int
    product_name: str
    price: float
    quantity: int

    class Config:
        orm_mode = True

class OrderResponse(BaseModel):
    id: int
    user_id: int
    status: str
    total_price: float
    items: List[OrderItemResponse]

    class Config:
        orm_mode = True

class CartItemResponse(BaseModel):
    id: int
    product_id: int
    product_name: str
    price: float
    quantity: int

    class Config:
        orm_mode = True
