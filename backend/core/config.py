import os 
from pathlib import Path
from dotenv import load_dotenv

# Xác định đường dẫn đến thư mục gốc của dự án (NT219_Secure_Payment_Project)
# Giả định file này nằm trong backend/core/
BASE_DIR = Path(__file__).resolve().parent.parent

# Tải biến môi trường từ file .env ở thư mục gốc
dotenv_path = BASE_DIR / '.env'
load_dotenv(dotenv_path=dotenv_path)

class Settings:
    """
    Cấu hình ứng dụng
    """
    # Stripe API keys
    STRIPE_PUBLIC_KEY:str = os.getenv("STRIPE_PUBLIC_KEY")
    STRIPE_SECRET_KEY:str = os.getenv("STRIPE_SECRET_KEY")

    # Project Directories
    BASE_DIR: Path = BASE_DIR
    TEMPLATES_DIR: Path = BASE_DIR / "frontend" / "templates"

    # Kiểm tra các biến môi trường quan trọng
    if not STRIPE_PUBLIC_KEY or not STRIPE_SECRET_KEY:
        raise ValueError("Lỗi: Vui lòng cung cấp STRIPE_PUBLIC_KEY và STRIPE_SECRET_KEY trong file .env")
    
settings = Settings()