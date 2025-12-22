FROM docker.io/library/python:3.11-slim

WORKDIR /app

# Thêm /app vào PYTHONPATH
ENV PYTHONPATH=/app

# Copy requirements và install dependencies
COPY requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy toàn bộ backend code vào /app/backend để giữ cấu trúc import
COPY . /app/backend

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
