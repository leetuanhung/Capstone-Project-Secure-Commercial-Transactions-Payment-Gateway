from pydantic_settings import BaseSettings
from typing import Optional



# bien moi truong la cac gia tri dươc luu trong hệ thống hoặc file env ma chuong trinh co the doc khi chay ma khong can lưu cứng trong code
class Settings(BaseSettings):
    # Database - Railway auto-injects these with POSTGRES_ prefix
    database_hostname: Optional[str] = None
    database_port: Optional[str] = "5432"
    database_password: Optional[str] = None
    database_name: Optional[str] = None
    database_username: Optional[str] = None
    
    # Railway also provides DATABASE_URL directly (fallback)
    DATABASE_URL: Optional[str] = None
    
    # JWT
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    
    # Stripe
    Stripe_Public_Key: str = "pk_test_dummy"
    Stripe_Secret_Key: str = "sk_test_dummy"
    
    # Encryption
    Key_AES: str
    USER_AES_KEY: Optional[str] = None
    
    class Config:
        env_file = ".env"
        extra = "ignore"
        case_sensitive = False  # Allow both uppercase and lowercase
    
    def get_database_url(self) -> str:
        """Get database URL from Railway DATABASE_URL or construct from parts"""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return f"postgresql://{self.database_username}:{self.database_password}@{self.database_hostname}:{self.database_port}/{self.database_name}"

settings = Settings()
