#!/usr/bin/env bash
# Render start script

set -o errexit

echo "🚀 Starting application..."

# Run database migrations if needed
# echo "Running database migrations..."
# alembic upgrade head

# Start the application
echo "Starting uvicorn server..."
cd /app
exec uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}
