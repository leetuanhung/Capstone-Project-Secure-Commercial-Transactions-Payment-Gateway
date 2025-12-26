# 🐳 Docker Deployment Guide - Secure Payment Gateway

Hướng dẫn deploy ứng dụng Payment Gateway lên Docker với đầy đủ backend, database, và nginx.

---

## 📋 Mục Lục
1. [Yêu Cầu Hệ Thống](#yêu-cầu-hệ-thống)
2. [Kiến Trúc Docker](#kiến-trúc-docker)
3. [Cấu Hình Môi Trường](#cấu-hình-môi-trường)
4. [Khởi Chạy Docker](#khởi-chạy-docker)
5. [Kiểm Tra & Testing](#kiểm-tra--testing)
6. [Troubleshooting](#troubleshooting)
7. [Production Deployment](#production-deployment)

---

## Yêu Cầu Hệ Thống

### Software Requirements
```bash
# 1. Docker Desktop (Windows/Mac) hoặc Docker Engine (Linux)
docker --version
# Expected: Docker version 20.10+ hoặc mới hơn

# 2. Docker Compose
docker-compose --version
# Expected: Docker Compose version 2.0+ hoặc mới hơn
```

### Hardware Requirements (Minimum)
- **CPU**: 2 cores
- **RAM**: 4GB
- **Disk**: 10GB free space
- **Network**: Internet connection (để pull images)

---

## Kiến Trúc Docker

### Container Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                         Internet                             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ :80, :443
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              NGINX Container (nt219_nginx)                   │
│  - TLS Termination                                           │
│  - Reverse Proxy                                             │
│  - Security Headers                                          │
│  - HTTP → HTTPS Redirect                                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ :8000 (internal)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│           FastAPI Backend (nt219_backend)                    │
│  - User Service                                              │
│  - Payment Service                                           │
│  - Order Service                                             │
│  - CSRF Protection                                           │
│  - Rate Limiting                                             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ :5432 (internal)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│         PostgreSQL Database (nt219_postgres)                 │
│  - User Data                                                 │
│  - Orders                                                    │
│  - Transactions                                              │
│  - Persistent Volume                                         │
└─────────────────────────────────────────────────────────────┘
```

### Docker Services

| Service | Container Name | Image | Ports | Purpose |
|---------|---------------|-------|-------|---------|
| **nginx** | nt219_nginx | nginx:stable-alpine | 80, 443 | TLS termination, reverse proxy |
| **backend** | nt219_backend | Custom (Dockerfile) | 8000 (internal) | FastAPI application |
| **db** | nt219_postgres | postgres:15-alpine | 5432 | PostgreSQL database |

### Volumes
```yaml
postgres_data:  # Persistent database storage
```

---

## Cấu Hình Môi Trường

### 1. Tạo File .env

**QUAN TRỌNG**: Không commit file `.env` vào Git!

```bash
# Copy từ template
cp .env.example .env

# Hoặc tạo mới
notepad .env  # Windows
nano .env     # Linux/Mac
```

### 2. Cấu Hình .env cho Docker

```bash
# ============================================
# DATABASE CONFIGURATION (Docker)
# ============================================
# IMPORTANT: Sử dụng service name 'db' thay vì 'localhost'
database_hostname=db
database_name=payment_gateway_db
database_port=5432
database_username=postgres
database_password=your_secure_password_here_change_me

# ============================================
# STRIPE API
# ============================================
Stripe_Secret_Key=sk_test_your_stripe_secret_key_here
Stripe_Publishable_Key=pk_test_your_stripe_publishable_key_here
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret_here

# ============================================
# JWT AUTHENTICATION
# ============================================
JWT_SECRET_KEY=your_super_secret_jwt_key_change_in_production
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# ============================================
# EMAIL SERVICE (AWS SES)
# ============================================
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
SENDER_EMAIL=noreply@yourdomain.com

# ============================================
# SECURITY
# ============================================
SECRET_KEY=your_secret_key_for_encryption_change_me
HMAC_SECRET=your_hmac_secret_key_change_me
ENCRYPTION_KEY=your_32_byte_base64_encryption_key_here

# ============================================
# APPLICATION
# ============================================
APP_ENV=development
DEBUG=true
ALLOWED_HOSTS=localhost,127.0.0.1,*.kesug.com
```

### 3. Tạo TLS Certificates

```bash
# Tạo thư mục certs nếu chưa có
mkdir -p backend/certs

# Generate self-signed certificate (for local dev)
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout backend/certs/localhost.key \
  -out backend/certs/localhost.crt \
  -days 365 \
  -subj "/C=VN/ST=HoChiMinh/L=HoChiMinh/O=SecureShop/CN=localhost"

# Verify certificates
ls -la backend/certs/
# Should see: localhost.crt, localhost.key
```

**⚠️ Production**: Sử dụng Let's Encrypt hoặc certificate từ CA trusted.

---

## Khởi Chạy Docker

### 1. Build Images

```bash
# Build tất cả services
docker-compose build

# Hoặc build với no-cache (force rebuild)
docker-compose build --no-cache

# Build specific service
docker-compose build backend
```

**Expected output:**
```
[+] Building 45.2s (12/12) FINISHED
 => [internal] load build definition from Dockerfile
 => => transferring dockerfile: 532B
 => [internal] load .dockerignore
 => [internal] load metadata for docker.io/library/python:3.11-slim
 => [1/6] FROM docker.io/library/python:3.11-slim
 => [2/6] WORKDIR /app
 => [3/6] RUN apt-get update && apt-get install -y gcc postgresql-client
 => [4/6] COPY requirements.txt /app/requirements.txt
 => [5/6] RUN pip install --no-cache-dir -r /app/requirements.txt
 => [6/6] COPY backend /app/backend
 => exporting to image
 => => writing image sha256:abc123...
```

### 2. Start Containers

```bash
# Start all services in detached mode
docker-compose up -d

# Hoặc start với logs visible
docker-compose up

# Start specific service
docker-compose up -d backend
```

**Expected output:**
```
[+] Running 4/4
 ✔ Network capstone-project_default  Created
 ✔ Volume "capstone-project_postgres_data"  Created
 ✔ Container nt219_postgres           Started
 ✔ Container nt219_backend            Started
 ✔ Container nt219_nginx              Started
```

### 3. Verify Containers

```bash
# Check running containers
docker-compose ps

# Expected output:
NAME               IMAGE                           COMMAND                  PORTS
nt219_backend      capstone-project-backend        "uvicorn backend.mai…"   8000/tcp
nt219_nginx        nginx:stable-alpine             "/docker-entrypoint.…"   0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
nt219_postgres     postgres:15-alpine              "docker-entrypoint.s…"   0.0.0.0:5432->5432/tcp
```

### 4. View Logs

```bash
# View all logs
docker-compose logs

# Follow logs (real-time)
docker-compose logs -f

# Logs for specific service
docker-compose logs -f backend
docker-compose logs -f db
docker-compose logs -f nginx

# Last 50 lines
docker-compose logs --tail=50 backend
```

---

## Kiểm Tra & Testing

### 1. Health Checks

```powershell
# Check nginx health
Invoke-WebRequest -Uri "https://localhost/health" -SkipCertificateCheck

# Check backend API
Invoke-WebRequest -Uri "https://localhost/docs" -SkipCertificateCheck

# Check database connection
docker exec -it nt219_postgres psql -U postgres -d payment_gateway_db -c "SELECT version();"
```

### 2. Test Endpoints

```powershell
# Test login page
Invoke-WebRequest -Uri "https://localhost/user_service/login" -SkipCertificateCheck

# Test API docs
Start-Process "https://localhost/docs"

# Test HTTP → HTTPS redirect
curl http://localhost
# Should return: 301 Moved Permanently → https://
```

### 3. Database Verification

```bash
# Enter PostgreSQL container
docker exec -it nt219_postgres psql -U postgres -d payment_gateway_db

# Run SQL queries
\dt               # List tables
\du               # List users
SELECT * FROM users LIMIT 5;
\q                # Exit
```

### 4. Backend Service Test

```bash
# Enter backend container
docker exec -it nt219_backend bash

# Check Python environment
python --version
pip list | grep fastapi

# Test import
python -c "from backend.main import app; print('OK')"

# Exit
exit
```

---

## Docker Commands Cheat Sheet

### Container Management

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose stop

# Restart services
docker-compose restart

# Stop and remove containers
docker-compose down

# Stop, remove containers + volumes (⚠️ DATA LOSS)
docker-compose down -v

# Remove all (containers, networks, images)
docker-compose down --rmi all -v
```

### Debugging

```bash
# Execute command in running container
docker exec -it nt219_backend bash
docker exec -it nt219_postgres psql -U postgres

# View container details
docker inspect nt219_backend

# View container stats (CPU, memory)
docker stats

# Copy files from container
docker cp nt219_backend:/app/logs/app.log ./local-logs/
```

### Database Management

```bash
# Create database backup
docker exec -t nt219_postgres pg_dump -U postgres payment_gateway_db > backup.sql

# Restore database
cat backup.sql | docker exec -i nt219_postgres psql -U postgres payment_gateway_db

# Reset database (⚠️ DATA LOSS)
docker-compose down -v
docker-compose up -d
```

---

## Troubleshooting

### ❌ Problem 1: Port Already in Use

**Error:**
```
Error response from daemon: Ports are not available: exposing port TCP 0.0.0.0:443 -> 0.0.0.0:0: listen tcp 0.0.0.0:443: bind: An attempt was made to access a socket in a way forbidden by its access permissions.
```

**Solution:**
```powershell
# Windows: Check port usage
netstat -ano | findstr ":443"
netstat -ano | findstr ":80"

# Kill process using port
taskkill /PID <PID> /F

# Or change port in Docker-compose.yml
ports:
  - "8080:80"      # Instead of 80:80
  - "8443:443"     # Instead of 443:443
```

### ❌ Problem 2: Database Connection Failed

**Error:**
```
sqlalchemy.exc.OperationalError: could not connect to server: Connection refused
```

**Solution:**
```bash
# 1. Check database is running
docker-compose ps db

# 2. Check logs
docker-compose logs db

# 3. Verify environment variable
docker exec -it nt219_backend env | grep database_hostname
# Should be: database_hostname=db (NOT localhost)

# 4. Wait for database to be ready
docker-compose up -d db
sleep 10
docker-compose up -d backend
```

### ❌ Problem 3: Import Errors

**Error:**
```
ModuleNotFoundError: No module named 'backend'
```

**Solution:**
```bash
# 1. Check PYTHONPATH
docker exec -it nt219_backend env | grep PYTHONPATH
# Should be: PYTHONPATH=/app

# 2. Verify file structure
docker exec -it nt219_backend ls -la /app/
docker exec -it nt219_backend ls -la /app/backend/

# 3. Rebuild image
docker-compose build --no-cache backend
docker-compose up -d backend
```

### ❌ Problem 4: TLS Certificate Error

**Error:**
```
SSL_ERROR_SELF_SIGNED_CERT
```

**Solution:**
```bash
# 1. Regenerate certificates
cd backend/certs
rm localhost.crt localhost.key
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout localhost.key \
  -out localhost.crt \
  -days 365 \
  -subj "/CN=localhost"

# 2. Trust certificate (Windows)
certutil -addstore -f "ROOT" backend\certs\localhost.crt

# 3. Or access with curl
curl -k https://localhost/docs  # -k = insecure, skip verification
```

### ❌ Problem 5: CSRF Token Error

**Error:**
```
403 Forbidden: CSRF validation failed
```

**Solution:**
```bash
# 1. Check cookie settings in backend/services/user_service/user.py
# For Docker with nginx, use:
secure_cookie = False  # If accessing via http://localhost
samesite = "lax"

# 2. Clear browser cookies
# DevTools → Application → Cookies → Clear all

# 3. Restart backend
docker-compose restart backend
```

### ❌ Problem 6: Slow Build Time

**Solution:**
```bash
# 1. Use BuildKit (faster)
DOCKER_BUILDKIT=1 docker-compose build

# 2. Use layer caching
# Dockerfile already optimized:
# - Copy requirements.txt first
# - Install dependencies
# - Copy source code last

# 3. Use .dockerignore
# Already configured to exclude:
# - __pycache__, venv, node_modules
# - .git, tests, docs
```

---

## Production Deployment

### Security Checklist

- [ ] **Change default passwords**
  ```bash
  database_password=<strong-random-password>
  JWT_SECRET_KEY=<cryptographically-secure-key>
  ```

- [ ] **Use real TLS certificates**
  ```bash
  # Let's Encrypt (recommended)
  certbot certonly --standalone -d yourdomain.com
  ```

- [ ] **Disable debug mode**
  ```bash
  DEBUG=false
  APP_ENV=production
  ```

- [ ] **Remove --reload flag**
  ```yaml
  # Docker-compose.yml
  command: uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 4
  ```

- [ ] **Enable firewall**
  ```bash
  # Only expose 80, 443
  # Block 8000, 5432 from outside
  ```

- [ ] **Setup monitoring**
  - Container health checks
  - Log aggregation (ELK, Splunk)
  - Metrics (Prometheus, Grafana)

- [ ] **Backup strategy**
  ```bash
  # Automated database backups
  0 2 * * * docker exec nt219_postgres pg_dump -U postgres payment_gateway_db > /backups/db_$(date +\%Y\%m\%d).sql
  ```

### Production Docker Compose

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  db:
    image: postgres:15-alpine
    container_name: payment_postgres_prod
    environment:
      POSTGRES_USER: ${database_username}
      POSTGRES_PASSWORD: ${database_password}
      POSTGRES_DB: ${database_name}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups  # Backup storage
    restart: always
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${database_username}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - backend_network

  backend:
    build: .
    container_name: payment_backend_prod
    expose:
      - "8000"
    env_file:
      - .env.production
    environment:
      - database_hostname=db
      - APP_ENV=production
      - DEBUG=false
    volumes:
      - ./logs:/app/logs
    command: uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 4
    depends_on:
      db:
        condition: service_healthy
    restart: always
    networks:
      - backend_network

  nginx:
    image: nginx:stable-alpine
    container_name: payment_nginx_prod
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./deploy/nginx/conf.d:/etc/nginx/conf.d:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro  # Real TLS certs
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - backend
    restart: always
    networks:
      - backend_network

volumes:
  postgres_data:

networks:
  backend_network:
    driver: bridge
```

**Deploy production:**
```bash
docker-compose -f docker-compose.prod.yml up -d
```

---

## Useful Resources

### Documentation
- [Docker Compose Reference](https://docs.docker.com/compose/)
- [FastAPI Deployment](https://fastapi.tiangolo.com/deployment/)
- [PostgreSQL Docker](https://hub.docker.com/_/postgres)
- [Nginx Configuration](https://nginx.org/en/docs/)

### Tools
- **Portainer**: Docker GUI management - `docker run -d -p 9000:9000 portainer/portainer-ce`
- **pgAdmin**: PostgreSQL GUI - `docker run -p 5050:80 dpage/pgadmin4`
- **Docker Desktop**: Visual container management

### Monitoring
```bash
# Install cAdvisor (Container metrics)
docker run -d -p 8080:8080 \
  --name cadvisor \
  --volume=/:/rootfs:ro \
  --volume=/var/run:/var/run:ro \
  gcr.io/cadvisor/cadvisor:latest
```

---

## Quick Start (TL;DR)

```bash
# 1. Clone repo
git clone <repo-url>
cd Capstone-Project-Secure-Commercial-Transactions-Payment-Gateway

# 2. Configure environment
cp .env.example .env
# Edit .env: Change database_hostname to 'db'

# 3. Generate TLS certs
mkdir -p backend/certs
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout backend/certs/localhost.key \
  -out backend/certs/localhost.crt \
  -days 365 -subj "/CN=localhost"

# 4. Build and run
docker-compose build
docker-compose up -d

# 5. Verify
docker-compose ps
curl -k https://localhost/docs

# 6. View logs
docker-compose logs -f
```

**Access:**
- **API Docs**: https://localhost/docs
- **Login**: https://localhost/user_service/login
- **Nginx Health**: https://localhost/health

---

## 🎯 Next Steps

1. ✅ **Test all endpoints** - Verify login, payment, orders
2. ✅ **Run attack scenarios** - Test security features from [ATTACK_SCENARIOS.md](ATTACK_SCENARIOS.md)
3. ✅ **Setup monitoring** - Container health, logs, metrics
4. ✅ **CI/CD Pipeline** - Automate build and deployment
5. ✅ **Production checklist** - Security hardening before go-live

---

*Document created for NT219 Capstone Project*  
*Last updated: December 2025*
