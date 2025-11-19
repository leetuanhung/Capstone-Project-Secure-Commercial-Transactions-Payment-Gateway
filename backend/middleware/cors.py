# backend/gateway/middleware/cors.py
from fastapi.middleware.cors import CORSMiddleware
import os

def setup_cors(app):
    """
    ✅ Cho phép frontend (HTML/JS) gọi API Gateway an toàn.
    
    Dev: HTTP only for development
    """
    # Development: HTTP only (HTTPS disabled)
    origins = [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:5173",   # Vite/React dev server
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
