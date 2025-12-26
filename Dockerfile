FROM docker.io/library/python:3.11-slim

WORKDIR /app

# Thêm /app vào PYTHONPATH
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements và install dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy toàn bộ source code
COPY backend /app/backend
COPY frontend /app/frontend

# Create logs directory
RUN mkdir -p /app/logs

# Expose port
EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
