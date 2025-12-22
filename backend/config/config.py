from pydantic_settings import BaseSettings
from typing import Optional
import os


# bien moi truong la cac gia tri dươc luu trong hệ thống hoặc file env ma chuong trinh co the doc khi chay ma khong can lưu cứng trong code
class Settings(BaseSettings):
    # Database config - required for production
    database_hostname: str = "localhost"
    database_port: str = "5432"
    database_password: str = ""
    database_name: str = "services"
    database_username: str = "postgres"
    
    # Auth config
    secret_key: str = "default-insecure-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    
    # Stripe config - optional for startup but required for payments
    Stripe_Public_Key: str = ""
    Stripe_Secret_Key: str = ""
    
    # Encryption keys
    Key_AES: Optional[str] = None
    USER_AES_KEY: Optional[str] = None
    
    class Config:
        env_file = ".env"
        extra = "ignore"

# Try to load settings, with fallback for missing .env
try:
    settings = Settings()
    print("✅ Settings loaded successfully")
except Exception as e:
    print(f"⚠️ Settings loading failed: {e}")
    # Create minimal settings for startup
    settings = Settings(
        database_hostname=os.getenv("database_hostname", "localhost"),
        database_password=os.getenv("database_password", ""),
        Stripe_Secret_Key=os.getenv("Stripe_Secret_Key", os.getenv("STRIPE_SECRET_KEY", "")),
        Stripe_Public_Key=os.getenv("Stripe_Public_Key", os.getenv("STRIPE_PUBLISHABLE_KEY", "")),
    )
    print("⚠️ Using fallback settings")
