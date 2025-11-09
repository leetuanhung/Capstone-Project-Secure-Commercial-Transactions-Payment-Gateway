#!/usr/bin/env python3
"""
Generate Production Keys Script
Tạo tất cả keys cần thiết cho production deployment
"""

import base64
import secrets

def generate_aes_key() -> str:
    """Generate AES-256 key (32 bytes)"""
    return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')

def generate_secret_key() -> str:
    """Generate JWT secret key"""
    return secrets.token_urlsafe(64)

def main():
    print("=" * 60)
    print("🔐 PRODUCTION KEYS GENERATOR")
    print("=" * 60)
    print()
    print("⚠️  QUAN TRỌNG: Lưu keys này vào .env hoặc Railway/Render variables")
    print("⚠️  KHÔNG BAO GIỜ commit keys vào Git!")
    print()
    print("-" * 60)
    
    # Generate USER_AES_KEY
    user_aes_key = generate_aes_key()
    print(f"USER_AES_KEY={user_aes_key}")
    print()
    
    # Generate Key_AES (legacy)
    key_aes = generate_aes_key()
    print(f"Key_AES={key_aes}")
    print()
    
    # Generate JWT secret
    secret_key = generate_secret_key()
    print(f"secret_key={secret_key}")
    print()
    
    print("-" * 60)
    print()
    print("📋 Copy toàn bộ keys trên và paste vào:")
    print("   - Railway: Settings → Variables")
    print("   - Render: Environment → Environment Variables")
    print("   - AWS/VPS: ~/.env file")
    print()
    print("✅ Sau khi paste, delete terminal history để bảo mật:")
    print("   PowerShell: Clear-History")
    print("   Bash: history -c")
    print()
    print("=" * 60)

if __name__ == "__main__":
    main()
