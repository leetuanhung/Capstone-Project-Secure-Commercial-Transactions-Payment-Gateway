"""
HTTPS Server Launcher for Payment Gateway
Chạy FastAPI với SSL/TLS certificates
"""
import os
import sys
from pathlib import Path

# Thêm backend vào path để import được
backend_path = Path(__file__).parent
sys.path.insert(0, str(backend_path.parent))

if __name__ == "__main__":
    import uvicorn
    
    # Đường dẫn certificates
    cert_dir = backend_path / "certs"
    certfile = cert_dir / "localhost.crt"
    keyfile = cert_dir / "localhost.key"
    
    if not certfile.exists() or not keyfile.exists():
        print("❌ ERROR: SSL certificates not found!")
        print(f"   Expected: {certfile}")
        print(f"             {keyfile}")
        print("\n   Generate certificates first:")
        print("   openssl req -x509 -newkey rsa:2048 -keyout backend/certs/localhost.key -out backend/certs/localhost.crt -days 365 -nodes")
        sys.exit(1)
    
    print("🔒 Starting HTTPS server with SSL/TLS...")
    print(f"   Certificate: {certfile}")
    print(f"   Key: {keyfile}")
    print("\n✅ Server will be available at: https://127.0.0.1:8000")
    print("   (Accept the self-signed certificate warning in browser)\n")
    
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        ssl_keyfile=str(keyfile),
        ssl_certfile=str(certfile)
    )
