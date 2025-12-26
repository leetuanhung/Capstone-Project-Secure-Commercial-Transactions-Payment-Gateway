from sqlalchemy import Column, Integer, String, Float, TIMESTAMP, ForeignKey, text, Text
from sqlalchemy.orm import relationship
from backend.database.database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    name_encrypted = Column(Text, nullable=True)
    email_encrypted = Column(Text, nullable=True)
    phone = Column(String, nullable=True)
    phone_encrypted = Column(Text, nullable=True)
    email_verified = Column(Integer, default=0)  # 0 = chưa xác thực, 1 = đã xác thực
    created_at = Column(TIMESTAMP(timezone=True), server_default=text("now()"))

    orders = relationship("Order", back_populates="user")
    cart_items = relationship("CartItem", back_populates="user")

class Product(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String)
    price = Column(Float, nullable=False)
    quantity = Column(Integer, default=0)
    image_url = Column(String)
    created_at = Column(TIMESTAMP(timezone=True), server_default=text("now()"))
    updated_at = Column(TIMESTAMP(timezone=True), server_default=text("now()"), onupdate=text("now()"))

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String, default="PENDING")
    total_price = Column(Float, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), server_default=text("now()"))

    user = relationship("User", back_populates="orders")
    items = relationship("OrderItem", back_populates="order")

class OrderItem(Base):
    __tablename__ = "order_items"
    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    product_name = Column(String, nullable=False)
    price = Column(Float, nullable=False)
    quantity = Column(Integer, nullable=False)

    order = relationship("Order", back_populates="items")


class PaymentHistory(Base):
    __tablename__ = "payment_history"
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # External / displayed order id used in the UI (e.g. ORD-XXXX, CART-XXXX)
    external_order_id = Column(String, nullable=False, index=True)

    amount = Column(Integer, nullable=False)
    currency = Column(String, nullable=False, default="VND")
    description = Column(String, nullable=True)
    status = Column(String, nullable=False, default="SUCCESS")

    stripe_transaction_id = Column(String, nullable=True)
    paid_at = Column(TIMESTAMP(timezone=True), server_default=text("now()"))

class CartItem(Base):
    __tablename__ = "cart_items"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    product_name = Column(String, nullable=False)
    price = Column(Float, nullable=False)
    quantity = Column(Integer, default=1)

    user = relationship("User", back_populates="cart_items")
