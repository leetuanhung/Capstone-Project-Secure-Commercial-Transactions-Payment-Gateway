# 🚀 Render Deployment Guide - Secure Payment Gateway

Hướng dẫn chi tiết để deploy ứng dụng Payment Gateway lên Render.com (Platform as a Service - PaaS).

---

## 📋 Mục Lục
1. [Tại Sao Chọn Render?](#tại-sao-chọn-render)
2. [Yêu Cầu Trước Khi Deploy](#yêu-cầu-trước-khi-deploy)
3. [Chuẩn Bị Repository](#chuẩn-bị-repository)
4. [Tạo PostgreSQL Database](#tạo-postgresql-database)
5. [Deploy Backend Service](#deploy-backend-service)
6. [Cấu Hình Environment Variables](#cấu-hình-environment-variables)
7. [Testing & Verification](#testing--verification)
8. [Troubleshooting](#troubleshooting)
9. [Cost & Limits](#cost--limits)

---

## Tại Sao Chọn Render?

### ✅ Ưu Điểm
- **Free Tier**: PostgreSQL 1GB + 750 hours web service miễn phí
- **Tự Động HTTPS**: SSL certificate tự động (Let's Encrypt)
- **Git Integration**: Auto-deploy khi push code
- **Zero DevOps**: Không cần config server, docker registry
- **PostgreSQL Managed**: Backup tự động, high availability

### ⚠️ Hạn Chế
- Free tier sleep sau 15 phút không hoạt động (cold start ~30s)
- 512MB RAM limit cho web service
- 1GB storage cho PostgreSQL
- Không có static IP (dùng domain)

### 🆚 So Với Các Platform Khác

| Feature | Render | Heroku | Railway | Fly.io |
|---------|--------|--------|---------|--------|
| Free PostgreSQL | ✅ 1GB | ❌ | ✅ 100MB | ❌ |
| Auto HTTPS | ✅ | ✅ | ✅ | ✅ |
| Cold Start | ~30s | ~60s | ~15s | ~10s |
| Pricing | $0-$7/mo | $5-$25/mo | $5-$20/mo | $0-$10/mo |

---

## Yêu Cầu Trước Khi Deploy

### 1. Tài Khoản & Dịch Vụ

- [ ] **GitHub Account**: Repository public/private
- [ ] **Render Account**: Đăng ký tại [render.com](https://render.com) (free)
- [ ] **Stripe Account**: Test/Live API keys
- [ ] **Email Service** (optional): AWS SES, SendGrid, hoặc Gmail SMTP

### 2. Kiểm Tra Code Local

```powershell
# Test app chạy được local
python backend/main.py
# hoặc
uvicorn backend.main:app --reload

# Verify health endpoint
curl http://localhost:8000/health
# Expected: {"status":"ok"}
```

### 3. Files Cần Thiết

Đã có sẵn trong repo:
- ✅ `Dockerfile.render` - Production Dockerfile
- ✅ `render.yaml` - Blueprint configuration
- ✅ `requirements.txt` - Python dependencies
- ✅ `.dockerignore` - Optimize build
- ✅ Health check endpoint: `/health`

---

## Chuẩn Bị Repository

### 1. Push Code Lên GitHub

```powershell
# Initialize git (nếu chưa có)
git init
git add .
git commit -m "Prepare for Render deployment"

# Add remote và push
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
```

### 2. Verify Files

```powershell
# Check critical files tồn tại
ls Dockerfile.render
ls render.yaml
ls requirements.txt
ls backend/main.py
```

**QUAN TRỌNG**: Đảm bảo `.env` file **KHÔNG** được commit:

```powershell
# Check .gitignore có chứa
cat .gitignore | Select-String ".env"
# Expected: .env
```

---

## Tạo PostgreSQL Database

### Option 1: Render PostgreSQL (Recommended)

1. **Truy cập Dashboard**
   - Go to: https://dashboard.render.com
   - Click **"New +"** → **"PostgreSQL"**

2. **Configure Database**
   ```
   Name: nt219-postgres
   Database: payment_gateway_db
   User: postgres_user
   Region: Singapore (gần Việt Nam nhất)
   Plan: Free
   ```

3. **Click "Create Database"**
   - Wait 2-3 minutes for provisioning
   - Database sẽ có format:
     ```
     postgresql://user:password@hostname:5432/database
     ```

4. **Copy Connection Details**
   - Vào tab **"Info"**
   - Copy các giá trị:
     - `Internal Database URL` (dùng cho Render services)
     - `External Database URL` (dùng cho local testing)
     - Hostname
     - Port: 5432
     - Database name
     - Username
     - Password

### Option 2: External PostgreSQL (Alternative)

Nếu bạn đã có PostgreSQL từ:
- **Supabase**: https://supabase.com (free 500MB)
- **ElephantSQL**: https://elephantsql.com (free 20MB)
- **Neon**: https://neon.tech (free 10GB)

Chỉ cần lấy connection string và config trong Render.

---

## Deploy Backend Service

### Method 1: Blueprint Deployment (Easiest)

**Sử dụng file `render.yaml` để tự động deploy**

1. **Go to Render Dashboard**
   - Click **"New +"** → **"Blueprint"**

2. **Connect Repository**
   - Select **"Connect GitHub"**
   - Authorize Render
   - Choose repository: `Capstone-Project-Secure-Commercial-Transactions-Payment-Gateway`

3. **Render Auto-Detects `render.yaml`**
   - Preview services to be created:
     - ✅ `nt219-backend` (Web Service)
   - Click **"Apply"**

4. **Configure Missing Environment Variables**
   
   Render sẽ yêu cầu nhập các biến `sync: false`:
   
   ```env
   # Database (from PostgreSQL service above)
   database_hostname=dpg-xxxxx-a.singapore-postgres.render.com
   database_port=5432
   database_username=postgres_user
   database_password=xxx_generated_password_xxx
   database_name=payment_gateway_db
   
   # Stripe (from Stripe Dashboard)
   STRIPE_SECRET_KEY=sk_test_51xxxxxxxxxxxx
   STRIPE_PUBLISHABLE_KEY=pk_test_xxxxxxxxxxxx
   STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxx
   ```

5. **Click "Create"**
   - Build process starts (~5-7 minutes first time)
   - Monitor logs in real-time

### Method 2: Manual Service Creation

1. **Create Web Service**
   - Click **"New +"** → **"Web Service"**
   - Connect GitHub repository
   - Configure:
     ```
     Name: nt219-backend
     Region: Singapore
     Branch: main
     Root Directory: (leave blank)
     Environment: Docker
     Dockerfile Path: ./Dockerfile.render
     ```

2. **Set Plan**
   - Select **"Free"**
   - Specs: 512MB RAM, 0.1 CPU

3. **Set Environment Variables** (see below)

4. **Click "Create Web Service"**

---

## Cấu Hình Environment Variables

### 1. Access Environment Settings

- Go to your service: **nt219-backend**
- Click **"Environment"** tab
- Click **"Add Environment Variable"**

### 2. Required Variables

```env
# ============================================
# DATABASE (from PostgreSQL service)
# ============================================
database_hostname=dpg-xxxxx-a.singapore-postgres.render.com
database_port=5432
database_username=postgres_user
database_password=your_generated_password
database_name=payment_gateway_db

# ============================================
# STRIPE API KEYS
# ============================================
# Get from: https://dashboard.stripe.com/test/apikeys
STRIPE_SECRET_KEY=sk_test_51SC0CKHxKDaqjWchvcG3zkVRWO7a5KjleXgOjfHdupQOYUQZGhIepLHUM098GTizgavcmKmbGj7PCI5CorktGaA400KvCp0Od5
STRIPE_PUBLISHABLE_KEY=pk_test_51SC0CKHxKDaqjWch3tQj2WK6hSv5vL4CJf9xZQUEVzN5xm9TJvH9u8Z9ZhK7yBpQN5xQK7PQZ5xQPQZ5xQPQZ00TEST1234
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret_from_stripe_cli

# ============================================
# JWT AUTHENTICATION
# ============================================
JWT_SECRET_KEY=your_random_secret_key_change_this_in_production
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# ============================================
# SECURITY & ENCRYPTION
# ============================================
SECRET_KEY=your_super_secret_encryption_key
HMAC_SECRET=your_hmac_verification_secret

# ============================================
# EMAIL (Optional - for OTP)
# ============================================
# Option 1: AWS SES
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
SENDER_EMAIL=noreply@yourdomain.com

# Option 2: SMTP (Gmail, SendGrid)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_FROM_EMAIL=noreply@yourdomain.com

# ============================================
# APPLICATION
# ============================================
ENVIRONMENT=production
PYTHONUNBUFFERED=1
PYTHONPATH=/app
ALLOWED_ORIGINS=*
DEBUG=false
```

### 3. Generate Secure Keys

```powershell
# Generate random secret keys
python -c "import secrets; print(secrets.token_urlsafe(32))"
# Copy output for JWT_SECRET_KEY, SECRET_KEY, HMAC_SECRET
```

### 4. Save Variables

- Click **"Save Changes"**
- Service sẽ tự động redeploy với config mới

---

## Testing & Verification

### 1. Check Deployment Status

```
Dashboard → nt219-backend → Events
```

**Expected timeline:**
```
[0:00] Build started
[0:30] Installing dependencies
[5:00] Building Docker image
[6:00] Image pushed
[6:30] Starting service
[7:00] ✅ Live
```

### 2. View Logs

```
Dashboard → nt219-backend → Logs
```

Look for:
```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:10000
```

### 3. Test Health Endpoint

```powershell
# Replace with your Render URL
curl https://nt219-backend.onrender.com/health

# Expected response:
# {"status":"ok"}
```

### 4. Test API Docs

```
https://nt219-backend.onrender.com/docs
```

Should see FastAPI Swagger UI.

### 5. Test User Registration

```powershell
# Register new user
$body = @{
    email = "test@example.com"
    password = "TestPassword123!"
    name = "Test User"
    phone = "0123456789"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://nt219-backend.onrender.com/user_service/register" `
    -Method Post `
    -Body $body `
    -ContentType "application/json"
```

### 6. Test Login

```powershell
# Login
Invoke-WebRequest -Uri "https://nt219-backend.onrender.com/user_service/login"
# Should return login page HTML
```

### 7. Database Verification

```powershell
# Connect to PostgreSQL from local
$env:DATABASE_URL="postgresql://user:password@hostname:5432/database"
psql $env:DATABASE_URL

# Run queries
\dt               # List tables
SELECT * FROM users;
\q
```

---

## Troubleshooting

### ❌ Problem 1: Build Failing

**Error:**
```
ERROR: Could not find a version that satisfies the requirement XXX
```

**Solution:**
```powershell
# Update requirements.txt locally
pip freeze > requirements.txt

# Test locally
pip install -r requirements.txt

# Push update
git add requirements.txt
git commit -m "Update dependencies"
git push
```

### ❌ Problem 2: Database Connection Failed

**Error in logs:**
```
sqlalchemy.exc.OperationalError: could not connect to server
```

**Solution:**

1. **Check environment variables**
   ```
   Dashboard → Environment → Verify all database_* variables
   ```

2. **Test connection from local**
   ```powershell
   psql "postgresql://user:pass@host:5432/db"
   ```

3. **Verify database is running**
   ```
   Dashboard → Databases → nt219-postgres → Status: Available
   ```

4. **Check IP whitelist** (if using external DB)
   - Render IPs are dynamic, must allow all IPs or use internal connection

### ❌ Problem 3: Health Check Failing

**Error:**
```
Health check failed: GET /health returned 503
```

**Solution:**

1. **Check health endpoint code**
   ```python
   # backend/main.py
   @app.get("/health")
   async def health():
       return {"status": "ok"}
   ```

2. **Verify PORT binding**
   ```python
   # Must bind to 0.0.0.0:$PORT (Render provides PORT env var)
   # Dockerfile.render already handles this
   ```

3. **Test locally**
   ```powershell
   $env:PORT=10000
   uvicorn backend.main:app --host 0.0.0.0 --port 10000
   curl http://localhost:10000/health
   ```

### ❌ Problem 4: Cold Start Timeout

**Symptom**: First request sau 15 phút trả về 503 hoặc timeout

**This is expected on free tier:**
- Free services sleep after 15 min inactivity
- First request wakes up service (~30-60s)
- Subsequent requests fast

**Solutions:**

1. **Upgrade to paid plan** ($7/month - no sleep)

2. **Use external cron job** to keep alive:
   ```
   # cron-job.org - ping every 14 minutes
   */14 * * * * curl https://your-app.onrender.com/health
   ```

3. **Show loading screen** on frontend for cold starts

### ❌ Problem 5: CSRF Token Errors

**Error:**
```
403 Forbidden: CSRF validation failed
```

**Solution:**

1. **Check cookie settings for production**
   ```python
   # backend/services/user_service/user.py
   secure_cookie = True  # For HTTPS (Render has auto HTTPS)
   samesite = "lax"
   ```

2. **Update ALLOWED_ORIGINS**
   ```env
   ALLOWED_ORIGINS=https://your-app.onrender.com
   ```

3. **Clear browser cookies** and retry

### ❌ Problem 6: Stripe Webhooks Not Working

**Error:**
```
Webhook signature verification failed
```

**Solution:**

1. **Update webhook endpoint in Stripe**
   ```
   Stripe Dashboard → Developers → Webhooks → Add endpoint
   URL: https://your-app.onrender.com/webhook
   Events: payment_intent.succeeded, payment_intent.failed
   ```

2. **Copy webhook secret**
   ```
   Stripe Dashboard → Webhooks → Click endpoint → Signing secret
   ```

3. **Update STRIPE_WEBHOOK_SECRET** in Render

4. **Test with Stripe CLI**
   ```powershell
   stripe listen --forward-to https://your-app.onrender.com/webhook
   stripe trigger payment_intent.succeeded
   ```

---

## CI/CD - Auto Deploy

### Enable Auto-Deploy

Render tự động deploy khi có commit mới:

1. **Dashboard → nt219-backend → Settings**

2. **Auto-Deploy: Yes** (default)

3. **Branch: main**

4. **Deploy Hook** (optional - for manual trigger):
   ```powershell
   # Trigger deploy via webhook
   curl -X POST https://api.render.com/deploy/srv-xxxxx?key=your-deploy-key
   ```

### Deploy Workflow

```
1. Developer: git push origin main
   ↓
2. GitHub: Webhook to Render
   ↓
3. Render: Start build
   ↓ (5-7 min)
4. Render: Docker build, push, deploy
   ↓
5. ✅ Live: https://your-app.onrender.com
```

### Rollback

```
Dashboard → nt219-backend → Events → Select previous deploy → "Redeploy"
```

---

## Cost & Limits

### Free Tier Specs

| Resource | Free Plan | Paid Plan |
|----------|-----------|-----------|
| **Web Service** | | |
| RAM | 512MB | 2GB - 32GB |
| CPU | 0.1 CPU | 0.5 - 8 CPU |
| Hours | 750 hours/month | Unlimited |
| Sleep | After 15 min | No sleep |
| Build Time | Free | Free |
| **PostgreSQL** | | |
| Storage | 1GB | 10GB - 1TB |
| Backups | 7 days | 30 days |
| Connections | 97 | 500+ |
| **Network** | | |
| Bandwidth | 100GB/month | Unlimited |
| SSL | Free (auto) | Free (auto) |

### When to Upgrade?

Upgrade khi:
- ✅ Traffic > 750 hours/month (24/7 = 744h)
- ✅ Need no cold starts (instant response)
- ✅ Database > 1GB
- ✅ Need > 512MB RAM (memory errors)
- ✅ Production environment

**Pricing:**
- Web Service: **$7/month** (starter)
- PostgreSQL: **$7/month** (starter)
- **Total: $14/month** for always-on production

---

## Monitoring & Logs

### 1. View Real-Time Logs

```
Dashboard → nt219-backend → Logs
```

**Filter by:**
- Error level
- Time range
- Search keywords

### 2. Metrics

```
Dashboard → nt219-backend → Metrics
```

View:
- Request rate (req/min)
- Response time (ms)
- Memory usage (MB)
- CPU usage (%)

### 3. Alerts (Paid Only)

```
Dashboard → nt219-backend → Settings → Notifications
```

Alert on:
- Service down
- Build failed
- Memory threshold

### 4. External Monitoring

**UptimeRobot** (free):
```
1. Sign up: uptimerobot.com
2. Add monitor:
   Type: HTTP(s)
   URL: https://your-app.onrender.com/health
   Interval: 5 minutes
3. Get alerts via email/SMS
```

---

## Security Best Practices

### 1. Environment Variables

- ✅ Never commit `.env` to Git
- ✅ Use Render's secret storage
- ✅ Rotate keys regularly
- ✅ Use different keys for test/prod

### 2. Database Security

- ✅ Use internal connection when possible
- ✅ Strong password (auto-generated)
- ✅ Enable SSL (default on Render)
- ✅ Regular backups

### 3. API Keys

```env
# Development
STRIPE_SECRET_KEY=sk_test_...

# Production
STRIPE_SECRET_KEY=sk_live_...
```

### 4. CORS Configuration

```python
# Production: Specific origins only
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Development: Allow all (testing only)
ALLOWED_ORIGINS=*
```

### 5. Rate Limiting

Already implemented in middleware:
```python
# backend/middleware/rate_limiter.py
RateLimitMiddleware(requests_per_minute=60)
```

---

## Production Checklist

Trước khi go-live:

- [ ] **Environment Variables**
  - [ ] All secrets set in Render
  - [ ] Production Stripe keys (sk_live_...)
  - [ ] Strong JWT_SECRET_KEY
  - [ ] EMAIL credentials configured

- [ ] **Database**
  - [ ] Backups enabled
  - [ ] Connection pooling configured
  - [ ] Migrations applied

- [ ] **Security**
  - [ ] HTTPS enforced (auto on Render)
  - [ ] CORS restricted to specific domains
  - [ ] Rate limiting enabled
  - [ ] CSRF protection active
  - [ ] Sensitive data encrypted

- [ ] **Monitoring**
  - [ ] UptimeRobot configured
  - [ ] Error logging working
  - [ ] Metrics tracking enabled

- [ ] **Testing**
  - [ ] All endpoints tested
  - [ ] Payment flow verified
  - [ ] OTP delivery working
  - [ ] Stripe webhooks configured

- [ ] **Documentation**
  - [ ] API docs accessible (/docs)
  - [ ] Environment variables documented
  - [ ] Deployment process documented

---

## Custom Domain (Optional)

### 1. Add Domain in Render

```
Dashboard → nt219-backend → Settings → Custom Domain
Add: yourdomain.com
```

### 2. Update DNS Records

```
Type: CNAME
Name: @  (or www)
Value: nt219-backend.onrender.com
TTL: 3600
```

### 3. Verify Domain

- Render auto-generates SSL certificate
- Wait 5-10 minutes for DNS propagation
- Test: https://yourdomain.com/health

### 4. Update Environment Variables

```env
ALLOWED_ORIGINS=https://yourdomain.com
```

---

## Useful Commands

### Local Testing Against Render DB

```powershell
# Set connection string
$env:DATABASE_URL="postgresql://user:pass@host.render.com:5432/db"

# Run app locally with Render DB
uvicorn backend.main:app --reload

# Run migrations
alembic upgrade head
```

### Database Operations

```powershell
# Connect to Render PostgreSQL
psql "$(render psql-url nt219-postgres)"

# Backup database
pg_dump "$(render psql-url nt219-postgres)" > backup.sql

# Restore database
psql "$(render psql-url nt219-postgres)" < backup.sql
```

### Trigger Manual Deploy

```powershell
# Via Render CLI
render deploy nt219-backend

# Via API (get key from Settings → Deploy Hook)
curl -X POST "https://api.render.com/deploy/srv-xxxxx?key=your-key"
```

---

## Next Steps

1. ✅ **Deploy application** following this guide
2. ✅ **Test all endpoints** thoroughly
3. ✅ **Setup monitoring** (UptimeRobot)
4. ✅ **Configure Stripe webhooks**
5. ✅ **Run security tests** from [ATTACK_SCENARIOS.md](ATTACK_SCENARIOS.md)
6. ✅ **Document API** for frontend team
7. ✅ **Setup staging environment** (optional - separate service)
8. ✅ **Load testing** before launch

---

## Support Resources

- **Render Docs**: https://render.com/docs
- **Render Community**: https://community.render.com
- **FastAPI Docs**: https://fastapi.tiangolo.com
- **PostgreSQL Docs**: https://www.postgresql.org/docs
- **Stripe Docs**: https://stripe.com/docs

---

*Document created for NT219 Capstone Project*  
*Platform: Render.com PaaS*  
*Last updated: December 2025*
