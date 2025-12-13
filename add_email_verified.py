"""
Migration script to add email_verified column to users table
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
    # Connect to database
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    cursor = conn.cursor()
    
    # Check if column exists
    cursor.execute("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name='users' AND column_name='email_verified';
    """)
    
    if cursor.fetchone():
        print("✅ Column 'email_verified' already exists!")
    else:
        # Add column
        cursor.execute("""
            ALTER TABLE users 
            ADD COLUMN email_verified INTEGER DEFAULT 0;
        """)
        conn.commit()
        print("✅ Successfully added 'email_verified' column to users table!")
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"❌ Error: {e}")
