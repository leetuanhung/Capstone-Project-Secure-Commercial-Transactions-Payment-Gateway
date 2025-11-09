#!/bin/sh
# Entrypoint script to handle PORT variable properly

# Get PORT from environment, default to 8000 if not set or empty
if [ -z "$PORT" ] || [ "$PORT" = "" ]; then
    PORT=8000
fi

echo "Starting uvicorn on port $PORT..."
exec uvicorn backend.main:app --host 0.0.0.0 --port $PORT
