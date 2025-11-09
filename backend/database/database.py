from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from ..config.config import settings
from sqlalchemy.orm import Session

# SQLALCHEMY_DATABASE_URL = 'postgresql://<username>:<password>@<ip-address/hostname>:<port>/<database_name'

# Use get_database_url() which supports both DATABASE_URL and individual vars
SQLALCHEMY_DATABASE_URL = settings.get_database_url()

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
