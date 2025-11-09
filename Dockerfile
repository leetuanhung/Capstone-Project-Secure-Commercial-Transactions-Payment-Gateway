FROM python:3.11-slim

WORKDIR /app

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Copy requirements first (for better caching)
COPY backend/requirements.txt /app/backend/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy application code
COPY backend /app/backend
COPY frontend /app/frontend

# Expose port (Railway will inject $PORT env variable)
EXPOSE 8000

# Run application with shell to properly handle PORT variable
CMD sh -c "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"
