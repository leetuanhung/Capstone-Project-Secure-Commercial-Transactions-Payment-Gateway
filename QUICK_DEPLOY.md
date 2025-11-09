# 🚀 HƯỚNG DẪN NHANH 5 PHÚT - Deploy lên Railway.app

## ⚡ Bước 1: Generate Keys (30 giây)

```bash
python generate_keys.py
```

**Output:**
```
USER_AES_KEY=abc123...
Key_AES=xyz789...
secret_key=def456...
```

→ **Copy tất cả keys này!**

---

## ⚡ Bước 2: Push code lên GitHub (1 phút)

```bash
git add .
git commit -m "Ready for deployment"
git push origin main
```

---

## ⚡ Bước 3: Deploy trên Railway.app (3 phút)

### 3.1. Đăng ký Railway:
1. Truy cập: https://railway.app/
2. Click **"Login"** → Sign in with GitHub
3. Authorize Railway

### 3.2. Tạo Project:
1. Click **"New Project"**
2. Chọn **"Deploy from GitHub repo"**
3. Chọn repository: `Ber173/NT219.Q11.ATTN`
4. Click **"Deploy Now"**

### 3.3. Add Database:
1. Click **"New"** → **"Database"** → **"Add PostgreSQL"**
2. Đợi 30 giây để database được tạo

### 3.4. Cấu hình Environment Variables:
1. Click vào **Backend service** (không phải database)
2. Click tab **"Variables"**
3. Click **"RAW Editor"**
4. Paste đoạn này (thay keys bằng keys từ Bước 1):

```bash
# Database (Railway tự động set)
database_hostname=${{Postgres.RAILWAY_PRIVATE_DOMAIN}}
database_port=5432
database_username=postgres
database_password=${{Postgres.POSTGRES_PASSWORD}}
database_name=railway

# Security Keys (PASTE KEYS TỪ BƯỚC 1)
USER_AES_KEY=<paste-key-bạn-generate>
Key_AES=<paste-key-bạn-generate>
secret_key=<paste-key-bạn-generate>

# JWT
algorithm=HS256
access_token_expire_minutes=60

# Stripe Test Keys (optional)
STRIPE_API_KEY=sk_test_51QSWl...
STRIPE_PUBLIC_KEY=pk_test_51QSWl...
```

5. Click **"Update Variables"**

### 3.5. Tạo Public URL:
1. Vẫn trong Backend service
2. Click tab **"Settings"**
3. Scroll xuống **"Networking"**
4. Click **"Generate Domain"**
5. Copy URL: `https://nt219q11attn-production.up.railway.app`

---

## ⚡ Bước 4: Test Website (1 phút)

### 4.1. Kiểm tra API docs:
```
https://your-app.up.railway.app/docs
```

→ Phải hiện Swagger UI ✅

### 4.2. Test đăng ký:
1. Mở: `https://your-app.up.railway.app/user_service/register`
2. Điền form:
   - Name: Test User
   - Email: test@example.com
   - Phone: 0901234567
   - Username: testuser
   - Password: Test@123
3. Click **Register**

### 4.3. Test đăng nhập:
1. Mở: `https://your-app.up.railway.app/user_service/login`
2. Username: `testuser`
3. Password: `Test@123`
4. Click **Login**

→ Phải redirect về trang welcome ✅

---

## 🎉 XONG RỒI!

Website của bạn đã online tại:
```
https://your-app-name.up.railway.app
```

Share link này cho mọi người để truy cập! 🚀

---

## 📊 Monitoring

### Xem logs:
1. Railway Dashboard → Click vào service
2. Tab **"Deployments"** → Click deployment mới nhất
3. Tab **"View Logs"**

### Xem metrics:
1. Tab **"Metrics"**
2. Theo dõi: CPU, RAM, Network

---

## 🔧 Troubleshooting

### ❌ "Application failed to respond"
→ Check logs xem lỗi gì

### ❌ "Database connection failed"
→ Verify database variables:
```bash
database_hostname=${{Postgres.RAILWAY_PRIVATE_DOMAIN}}
```

### ❌ "Module not found"
→ Redeploy:
1. Tab "Deployments"
2. Click "..." → "Redeploy"

---

## 💰 Chi phí

- **Free tier:** $5 credit/tháng (~550 giờ runtime)
- **Đủ cho:** Demo, presentation, testing
- **Upgrade:** $5/tháng nếu cần thêm

---

## 📱 Mobile Access

Share link này để mọi người truy cập bằng điện thoại:

```
https://your-app.up.railway.app
```

Hoặc tạo QR code: https://www.qr-code-generator.com/

---

## 🎓 Next Steps

1. ✅ Custom domain (nếu có)
2. ✅ Setup monitoring (Sentry)
3. ✅ Enable auto-deploy (mỗi lần push GitHub → tự deploy)
4. ✅ Add collaborators

---

## 🆘 Cần giúp?

- Railway Docs: https://docs.railway.app/
- Discord: https://discord.gg/railway
- File `DEPLOYMENT.md` trong project có hướng dẫn chi tiết hơn

