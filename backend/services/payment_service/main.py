"""
security.py
---------------------------------------
Các hàm bảo mật cơ bản cho hệ thống:
 - Hash & verify mật khẩu (bcrypt)
 - Cấu hình Stripe API key (nếu cần)
"""

import os
from dotenv import load_dotenv
import stripe
from passlib.context import CryptContext

# 🔧 Load biến môi trường từ .env
load_dotenv()

# 🔐 Stripe API Key (nếu có sử dụng trong hệ thống)
stripe.api_key = os.getenv("STRIPE_API_KEY")

# 🧩 Cấu hình bcrypt để hash password
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# -------------------------------
# 🔒 HÀM HASH & VERIFY MẬT KHẨU
# -------------------------------
def hash(password: str) -> str:
    """
    Hash mật khẩu người dùng bằng bcrypt.
    Giới hạn 72 ký tự vì bcrypt chỉ xử lý tối đa 72 bytes.
    """
    password_str = str(password)[:72]
    return pwd_context.hash(password_str)


def verify(plain_password: str, hashed_password: str) -> bool:
    """
    Kiểm tra mật khẩu gốc và hash có khớp không.
    """
    return pwd_context.verify(plain_password, hashed_password)
