from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from ..config.config import settings
from sqlalchemy.orm import Session

# SQLALCHEMY_DATABASE_URL = 'postgresql://<username>:<password>@<ip-address/hostname>:<port>/<database_name'

SQLALCHEMY_DATABASE_URL = (
    f"postgresql://{settings.database_username}:{settings.database_password}"
    f"@{settings.database_hostname}:{settings.database_port}/{settings.database_name}"
)

#SQLALCHEMY_DATABASE_URL = "postgresql://data_xx7b_user:EJCa3IByt0Rp2gLdM6jmZpiLSaWID7V9@dpg-d54c4lshg0os739d2tlg-a/data_xx7b"

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()  # tạo session mới
    try:
        yield db  # cung cấp session cho endpoint
    finally:
        db.close()  # đảm bảo đóng session


# user gọi API -> Fast api gọi get_db() -> Tạo session -> truyền vào endpoint -> đóng session
