from email import header
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from .. import database
from fastapi import Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from ..config.config import settings
from backend.database.database import get_db
from backend.schemas.token import Token, TokenData
from backend.models import models

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
# SECRET_KEY
# ALGORITHM
# EXPIRATION: thoi gian het han

# jwr dung de ma hóa, giải mã
# token: chuỗi jwt được client gửi lên
# secret_key: chuỗi bí mật dùng đẻ xác thực chuỗi và token, server dùng để keiemr tra xem token có bị sửa đổi không
# ALGORITHM: thuật toán dùng để mã hóa và giải mã jwt ("hs256")
# payload: sau khi giải mã token - thường là một dictionary chứa dữ liệu mà ta đã mã hóa trước đó
SECRET_KEY = settings.secret_key
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes


def create_access_token(data: dict):
    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encodeed_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encodeed_jwt


def verify_access_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        id: int = payload.get("user_id")
        if id is None:
            raise credentials_exception
        token_data = TokenData(
            id=id
        )  # chuyển dữ liệu thô từ jwt sang một model dữ liệu có kiểm soát
    # nếu id không phải là chuỗi hoặc thiếu dữ liệu bắt buộc thì báo lỗi => điều này khiên code am toàn hơn thay vì chỉ tin vào dứ liệu thô từ token
    except JWTError:
        raise credentials_exception
    return token_data

    """Khi server nhận được token, dòng lệnh trên sẽ:

Giải mã (decode) JWT → lấy phần nội dung (payload).

Kiểm tra chữ ký (signature) của token bằng SECRET_KEY và ALGORITHM.

Kiểm tra thời gian hết hạn (exp) nếu có.

Nếu token hợp lệ, trả về nội dung (payload).
Nếu token sai hoặc hết hạn, sẽ ném lỗi (jwt.ExpiredSignatureError, jwt.InvalidTokenError, v.v.)."""


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="could not validate credentials",
        headers={"www-Authenticate": "Bearer"},
    )
    token = verify_access_token(token, credentials_exception)
    user = db.query(models.User).filter(models.User.id == token.id).first()
    return user
