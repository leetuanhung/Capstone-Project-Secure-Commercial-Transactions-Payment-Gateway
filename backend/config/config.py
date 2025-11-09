from pydantic_settings import BaseSettings



# bien moi truong la cac gia tri dươc luu trong hệ thống hoặc file env ma chuong trinh co the doc khi chay ma khong can lưu cứng trong code
class Settings(BaseSettings):
    database_hostname: str
    database_port: str
    database_password: str
    database_name: str
    database_username: str
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int
    Stripe_Public_Key: str
    Stripe_Secret_Key: str
    Key_AES: str
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
