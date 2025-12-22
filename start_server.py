#!/usr/bin/env python3
"""
Render startup script with error handling
"""
import sys
import os

# Print diagnostic info
print("="*60)
print("🚀 Starting Payment Gateway Backend")
print("="*60)
print(f"Python version: {sys.version}")
print(f"Python path: {sys.path}")
print(f"Current directory: {os.getcwd()}")
print(f"PYTHONPATH env: {os.getenv('PYTHONPATH', 'Not set')}")
print(f"PORT env: {os.getenv('PORT', 'Not set')}")
print("="*60)

# Check directory structure
print("\n📁 Directory structure:")
import subprocess
subprocess.run(["ls", "-la", "/app"])
print("\n📁 Backend directory:")
subprocess.run(["ls", "-la", "/app/backend"])

# Try to import backend
print("\n🔍 Testing imports...")
try:
    import backend
    print(f"✅ backend package found at: {backend.__file__}")
except ImportError as e:
    print(f"❌ Failed to import backend: {e}")
    sys.exit(1)

try:
    from backend import main
    print(f"✅ backend.main imported successfully")
except Exception as e:
    print(f"❌ Failed to import backend.main: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Start uvicorn
print("\n🚀 Starting uvicorn...")
port = int(os.getenv("PORT", "10000"))
print(f"   Binding to 0.0.0.0:{port}")

import uvicorn
uvicorn.run(
    "backend.main:app",
    host="0.0.0.0",
    port=port,
    log_level="info"
)
