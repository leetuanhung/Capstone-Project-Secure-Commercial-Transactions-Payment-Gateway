from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from backend.database.database import get_db
from backend.models.models import Order, OrderItem, Product, CartItem
from backend.models.models import PaymentHistory
from backend.schemas.order import OrderCreate, OrderResponse, CartItemResponse
from fastapi import APIRouter, Form, Request, HTTPException, FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
import secrets
from backend.utils.logger import get_application_logger
from backend.oauth2 import oauth2
from sqlalchemy import desc
# -- KHỞI TẠO --
app = FastAPI(title="order Service")
router = APIRouter()
logger = get_application_logger(__name__)
# Fix đường dẫn templates
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
template = Jinja2Templates(directory=str(BASE_DIR / "frontend" / "templates"))

# -- DATABASE MOCK --
MOCK_ORDERS = [
    {
        "id": "ORD-" + secrets.token_hex(4).upper(), 
        "amount": 990000, 
        "currency": "VND", 
        "description": "Subscription for Secure Payment Service", 
        "status": "PENDING",
        "image": "https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=400&h=300&fit=crop"
    },
    {
        "id": "ORD-" + secrets.token_hex(4).upper(), 
        "amount": 1590000, 
        "currency": "VND", 
        "description": "Premium Security Package (1 Year)", 
        "status": "PENDING",
        "image": "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=400&h=300&fit=crop"
    },
    {
        "id": "ORD-" + secrets.token_hex(4).upper(), 
        "amount": 490000, 
        "currency": "VND", 
        "description": "Data Encryption Toolkit", 
        "status": "PENDING",
        "image": "https://images.unsplash.com/photo-1555949963-ff9fe0c870eb?w=400&h=300&fit=crop"
    },
    {
        "id": "ORD-" + secrets.token_hex(4).upper(), 
        "amount": 100000, 
        "currency": "VND", 
        "description": "LÊ VĂN THỨC", 
        "status": "PENDING",
        "image": "/static/images/LVT.jpg"  # Đường dẫn local
    },
    {
        "id": "ORD-" + secrets.token_hex(4).upper(), 
        "amount": 500, 
        "currency": "VND", 
        "description": "VÕ NGUYÊN KHOA", 
        "status": "PENDING",
        "image": "/static/images/VNK.jpg"
    }
]

CART = []
# -- ROUTES --


def _require_login(request: Request) -> bool:
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
    else:
        token = request.cookies.get("access_token")
    return bool(token and oauth2.verify_access_token(token))


@router.get("/orders", response_class=HTMLResponse)
async def list_orders(request: Request):
    if not _require_login(request):
        return RedirectResponse(url="/user_service/login", status_code=303)

    logger.info(
        "Orders page accessed",
        extra={"ip": request.client.host}
    )
    return template.TemplateResponse("orders.html", {"request": request, "orders": MOCK_ORDERS, "cart": CART})


@router.get("/add_to_cart", tags=["Cart"])
async def add_to_cart(order_id: str, quantity: int = 1):
    
    logger.info(f"Item added to cart: {order_id}, quantity: {quantity}")
    
    # Validate quantity
    if quantity < 1:
        quantity = 1
    if quantity > 99:
        quantity = 99
    
    order = next((o for o in MOCK_ORDERS if o["id"] == order_id), None)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    # Check if item already in cart
    existing_item = next((item for item in CART if item["id"] == order_id), None)
    if existing_item:
        # Update quantity if already exists
        existing_item["quantity"] = existing_item.get("quantity", 1) + quantity
        return RedirectResponse(url="/order_service/orders?message=Đã cập nhật số lượng", status_code=302)
    
    # Add new item with quantity
    cart_item = order.copy()
    cart_item["quantity"] = quantity
    CART.append(cart_item)
    return RedirectResponse(url="/order_service/orders", status_code=303)

@router.get("/cart", response_class=HTMLResponse, tags=["Cart"])
async def view_cart(request: Request, db: Session = Depends(get_db)):
    if not _require_login(request):
        return RedirectResponse(url="/user_service/login", status_code=303)

    cookie_user_id = request.cookies.get("user_id")
    history: list[dict] = []
    try:
        if cookie_user_id:
            user_id_int = int(cookie_user_id)
            rows = (
                db.query(PaymentHistory)
                .filter(PaymentHistory.owner_id == user_id_int)
                .order_by(desc(PaymentHistory.paid_at))
                .limit(20)
                .all()
            )
            history = [
                {
                    "id": r.external_order_id,
                    "amount": r.amount,
                    "currency": r.currency,
                    "description": r.description,
                    "status": r.status,
                    "paid_at": (r.paid_at.isoformat(sep=" ", timespec="seconds") if r.paid_at else ""),
                }
                for r in rows
            ]
    except Exception:
        history = []
    total = sum(item["amount"] for item in CART)
    return template.TemplateResponse("cart.html", {
        "request": request,
        "cart": CART,
        "total": total,
        "history": history,
    })

@router.get("/remove_from_cart", tags=["Cart"])
async def remove_from_cart(order_id:str):
    # Keep this consistent with other cart operations
    # (public access here would still look like a 'logged-in' session).
    # Note: cannot take Request in signature without changing route shape.
    global CART
    CART = [item for item in CART if item["id"] != order_id]
    return RedirectResponse(url="/order_service/cart", status_code=303)

""" @router.get("/", response_model=List[OrderResponse])
def get_orders(db: Session = Depends(get_db)):
    return db.query(Order).all()

@router.post("/", response_model=OrderResponse)
def create_order(order: OrderCreate, db: Session = Depends(get_db)):
    cart_items = db.query(CartItem).filter(CartItem.user_id == order.user_id).all()
    if not cart_items:
        raise HTTPException(status_code=400, detail="Cart is empty")
    
    total_price = sum(item.price * item.quantity for item in cart_items)
    new_order = Order(owner_id=order.user_id, total_price=total_price)
    db.add(new_order)
    db.commit()
    db.refresh(new_order)

    for item in cart_items:
        order_item = OrderItem(
            order_id=new_order.id,
            product_id=item.product_id,
            product_name=item.product_name,
            price=item.price,
            quantity=item.quantity
        )
        db.add(order_item)
        db.commit()


    db.query(CartItem).filter(CartItem.user_id == order.user_id).delete()
    db.commit()
    db.refresh(new_order)
    return new_order


@router.get("/cart/{user_id}", response_model=List[CartItemResponse])
def view_cart(user_id: int, db: Session = Depends(get_db)):
    return db.query(CartItem).filter(CartItem.user_id == user_id).all()


@router.post("/cart/{user_id}/{product_id}", response_model=CartItemResponse)
def add_to_cart(user_id: int, product_id: int, quantity: int = 1, db: Session = Depends(get_db)):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    cart_item = CartItem(
        user_id=user_id,
        product_id=product.id,
        product_name=product.name,
        price=product.price,
        quantity=quantity
    )
    db.add(cart_item)
    db.commit()
    db.refresh(cart_item)
    return cart_item


@router.delete("/cart/{user_id}/{cart_item_id}")
def remove_from_cart(user_id: int, cart_item_id: int, db: Session = Depends(get_db)):
    item = db.query(CartItem).filter(CartItem.id == cart_item_id, CartItem.user_id == user_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Cart item not found")
    db.delete(item)
    db.commit()
    return {"message": "Cart item removed"}


 """