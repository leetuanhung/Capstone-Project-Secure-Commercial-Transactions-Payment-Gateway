"""
Script to clear all users from database
"""
import psycopg2
from dotenv import load_dotenv
import os

load_dotenv()

# Database config
DB_HOST = os.getenv("database_hostname", "localhost")
DB_PORT = os.getenv("database_port", "5432")
DB_NAME = os.getenv("database_name", "postgres")
DB_USER = os.getenv("database_username", "postgres")
DB_PASSWORD = os.getenv("database_password", "postgres")

try:
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    cursor = conn.cursor()
    
    # Xóa theo thứ tự (foreign key constraints)
    print("🗑️ Đang xóa orders...")
    cursor.execute("DELETE FROM orders;")
    
    print("🗑️ Đang xóa users...")
    cursor.execute("DELETE FROM users;")
    
    conn.commit()
    
    # Đếm số records còn lại
    cursor.execute("SELECT COUNT(*) FROM orders;")
    orders_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM users;")
    users_count = cursor.fetchone()[0]
    
    print(f"✅ Đã xóa toàn bộ data!")
    print(f"   - Orders: {orders_count}")
    print(f"   - Users: {users_count}")
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"❌ Error: {e}")
