# backend/gateway/middleware/cors.py
from fastapi.middleware.cors import CORSMiddleware
import os

def setup_cors(app):
    """
    ✅ Cho phép frontend (HTML/JS) gọi API Gateway an toàn.
    
    Dev: accepts both http and https localhost
    Prod: should only allow https origins
    """
    # Environment-aware origins
    env = os.getenv("ENV", "development")
    
    if env == "production":
        # Production: HTTPS only
        origins = [
            "https://yourdomain.com",
            "https://www.yourdomain.com",
        ]
    else:
        # Development: allow both HTTP and HTTPS for localhost
        origins = [
            "http://127.0.0.1:8000",
            "http://localhost:8000",
            "https://127.0.0.1",
            "https://localhost",
            "https://127.0.0.1:443",
            "https://localhost:443",
            "http://127.0.0.1:5173",   # Vite/React dev server
        ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
