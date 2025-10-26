# backend/gateway/middleware/cors.py
from fastapi.middleware.cors import CORSMiddleware

def setup_cors(app):
    """
    ✅ Cho phép frontend (HTML/JS) gọi API Gateway an toàn.
    """
    origins = [
        "http://127.0.0.1:8000",   # local
        "http://localhost:8000",
        "http://127.0.0.1:5173",   # Vite hoặc React dev
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
