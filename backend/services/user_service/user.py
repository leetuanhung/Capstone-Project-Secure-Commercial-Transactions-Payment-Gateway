from fastapi import APIRouter, Form, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sqlalchemy.orm import Session
from backend.database.database import get_db
from backend.models.models import User
from backend.utils import crypto
from backend.oauth2 import oauth2

router = APIRouter(prefix="/auth", tags=["Authentication"])

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend" / "templates"))


@router.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    print(f"=== LOGIN ATTEMPT ===")
    print(f"Username: {username}")
    print(f"Password: {password}")
    
    user_db = db.query(User).filter(User.name == username).first()
    
    if not user_db:
        print("ERROR: User not found")
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Email hoặc mật khẩu không đúng"
        })
    
    print(f"User found: {user_db.name} ({user_db.email})")
    print(f"Stored hash: {user_db.password}")
    
    is_valid = crypto.verify(password, user_db.password)
    print(f"Password valid: {is_valid}")
    
    if not is_valid:
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Email hoặc mật khẩu không đúng"
        })
    access_token = oauth2.create_access_token(data={"user_id": user_db.id})
    
    print(f"SUCCESS: Login successful for user {user_db.name}")
    return templates.TemplateResponse("welcome.html", {
        "request": request, 
        "username": user_db.name, 
        "access_token": access_token
    })

@router.get("/register", response_class=HTMLResponse)
async def register_get(request: Request):
    return templates.TemplateResponse("register.html", {
        "request": request, 
        "error": None
    })

@router.post("/register", response_class=HTMLResponse)
async def register_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    
    print(f"=== REGISTER ATTEMPT ===")
    print(f"Name: {name}")
    print(f"Email: {email}")
    print(f"Password: {password}")
    print(f"Confirm: {confirm_password}")
    
    exists_email = db.query(User).filter(User.email == email).first()
    if exists_email:
        print("ERROR: Email already exists")
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Email đã tồn tại"
        })
    
    if password != confirm_password:
        print("ERROR: Passwords don't match")
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Mật khẩu không khớp"
        })
    
    if len(password) < 6:
        print("ERROR: Password too short")
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": "Mật khẩu phải có ít nhất 6 ký tự"
        })
    
    try:
        hashed_pass = crypto.hash(password)
        new_user = User(name=name, email=email, password=hashed_pass)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        print(f"SUCCESS: User created with ID: {new_user.id}")
        print(f"Redirecting to /auth/auth/login")

        return RedirectResponse(
            url="/", 
            status_code=303
        )
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        db.rollback()
        return templates.TemplateResponse("register.html", {
            "request": request, 
            "error": f"Lỗi server: {str(e)}"
        })