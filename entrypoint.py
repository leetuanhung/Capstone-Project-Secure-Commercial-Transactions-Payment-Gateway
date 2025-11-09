#!/usr/bin/env python3
"""
Entrypoint script to properly handle PORT environment variable
"""
import os
import sys

# Get PORT from environment, default to 8000
port = os.environ.get('PORT', '8000')

# Ensure port is valid integer
try:
    port_int = int(port)
    if port_int < 1 or port_int > 65535:
        print(f"Invalid port {port}, using default 8000")
        port = '8000'
except (ValueError, TypeError):
    print(f"Invalid PORT value '{port}', using default 8000")
    port = '8000'

print(f"Starting uvicorn on port {port}...")

# Run uvicorn
os.execvp('uvicorn', [
    'uvicorn',
    'backend.main:app',
    '--host', '0.0.0.0',
    '--port', port
])
