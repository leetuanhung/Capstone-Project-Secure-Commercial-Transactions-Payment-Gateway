#!/usr/bin/env python3
"""
Render startup script with comprehensive error handling
"""
import sys
import os
import traceback

# Print diagnostic info
print("="*60)
print("🚀 Starting Payment Gateway Backend")
print("="*60)
print(f"Python version: {sys.version}")
print(f"Current directory: {os.getcwd()}")
print(f"PORT env: {os.getenv('PORT', 'Not set')}")
print("="*60)

# Check directory structure
print("\n📁 Checking directory structure...")
try:
    import subprocess
    subprocess.run(["ls", "-la", "/app"], check=False)
    print("\n📁 Backend directory:")
    subprocess.run(["ls", "-la", "/app/backend"], check=False)
except Exception as e:
    print(f"⚠️ Could not list directories: {e}")

# Check Python path
print("\n🔍 Python path:")
for p in sys.path:
    print(f"   {p}")

# Try to import backend package
print("\n🔍 Testing backend package import...")
try:
    import backend
    print(f"✅ backend package found at: {backend.__file__ if hasattr(backend, '__file__') else 'built-in'}")
except ImportError as e:
    print(f"❌ CRITICAL: Failed to import backend package: {e}")
    print("\n🔍 Attempting to add /app to sys.path...")
    if '/app' not in sys.path:
        sys.path.insert(0, '/app')
    try:
        import backend
        print(f"✅ backend package found after path adjustment")
    except ImportError as e2:
        print(f"❌ Still failed: {e2}")
        print("\nℹ️ Starting minimal health server instead...")
        # Start minimal FastAPI server to bind port
        from fastapi import FastAPI
        import uvicorn
        
        minimal_app = FastAPI()
        
        @minimal_app.get("/")
        @minimal_app.get("/health")
        def health():
            return {
                "status": "degraded",
                "error": "Backend module import failed",
                "detail": str(e2)
            }
        
        port = int(os.getenv("PORT", "10000"))
        print(f"\n🚀 Starting minimal health server on 0.0.0.0:{port}")
        uvicorn.run(minimal_app, host="0.0.0.0", port=port)
        sys.exit(0)

# Try to import backend.main
print("\n🔍 Testing backend.main import...")
try:
    from backend import main
    print(f"✅ backend.main imported successfully")
    print(f"   App object: {main.app}")
except Exception as e:
    print(f"❌ CRITICAL: Failed to import backend.main")
    print(f"   Error: {e}")
    print("\n📋 Full traceback:")
    traceback.print_exc()
    
    print("\nℹ️ Starting minimal health server instead...")
    from fastapi import FastAPI
    import uvicorn
    
    minimal_app = FastAPI()
    
    @minimal_app.get("/")
    @minimal_app.get("/health")
    def health():
        return {
            "status": "degraded", 
            "error": "backend.main import failed",
            "detail": str(e),
            "traceback": traceback.format_exc()
        }
    
    port = int(os.getenv("PORT", "10000"))
    print(f"\n🚀 Starting minimal health server on 0.0.0.0:{port}")
    uvicorn.run(minimal_app, host="0.0.0.0", port=port)
    sys.exit(0)

# Start uvicorn with the real app
print("\n🚀 Starting uvicorn with backend.main:app...")
port = int(os.getenv("PORT", "10000"))
print(f"   Binding to 0.0.0.0:{port}")
print("="*60)

import uvicorn
try:
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=port,
        log_level="info"
    )
except Exception as e:
    print(f"\n❌ CRITICAL: Uvicorn failed to start: {e}")
    traceback.print_exc()
    sys.exit(1)
