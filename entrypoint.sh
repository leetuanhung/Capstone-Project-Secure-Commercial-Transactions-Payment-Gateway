#!/bin/sh
# Entrypoint script to handle PORT variable properly

# Use PORT from environment, default to 8000 if not set
PORT=${PORT:-8000}

echo "Starting uvicorn on port $PORT..."
exec uvicorn backend.main:app --host 0.0.0.0 --port "$PORT"
