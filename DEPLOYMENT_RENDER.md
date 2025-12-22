# 🚀 HƯỚNG DẪN DEPLOY LÊN RENDER

## 📋 Yêu cầu trước khi deploy

1. **Tài khoản Render**: Đăng ký tại [render.com](https://render.com)
2. **GitHub Repository**: Push code lên GitHub
3. **Stripe Account**: Có Stripe API keys

---

## 🎯 PHƯƠNG ÁN 1: Deploy tự động với Blueprint (Khuyến nghị)

### Bước 1: Push code lên GitHub

```bash
git add .
git commit -m "Prepare for Render deployment"
git push origin main
```

### Bước 2: Deploy từ Render Dashboard

1. Đăng nhập vào [Render Dashboard](https://dashboard.render.com)
2. Click **"New +"** → **"Blueprint"**
3. Chọn repository GitHub của bạn
4. Render sẽ tự động phát hiện file `render.yaml`
5. Click **"Apply"**

### Bước 3: Cấu hình Environment Variables

Sau khi services được tạo, vào từng service và thêm các biến môi trường:

#### Backend Service Environment Variables:

```
# Stripe (REQUIRED)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Email (Optional)
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_EMAIL=noreply@yourdomain.com

# CORS (Update with your frontend URL)
ALLOWED_ORIGINS=https://your-frontend.onrender.com
```

### Bước 4: Khởi tạo Database

Sau khi PostgreSQL service chạy, connect và chạy migrations:

1. Vào PostgreSQL service → **Connect** → Copy connection string
2. Sử dụng tool như TablePlus hoặc DBeaver để connect
3. Hoặc chạy migrations tự động (nếu có Alembic)

---

## 🎯 PHƯƠNG ÁN 2: Deploy thủ công từng service

### Bước 1: Tạo PostgreSQL Database

1. Dashboard → **"New +"** → **"PostgreSQL"**
2. Cấu hình:
   - **Name**: `nt219-postgres`
   - **Database**: `payment_gateway`
   - **User**: `postgres`
   - **Region**: `Singapore`
   - **Plan**: `Free`

### Bước 2: Tạo Web Service (Backend)

1. Dashboard → **"New +"** → **"Web Service"**
2. Chọn GitHub repository
3. Cấu hình:
   - **Name**: `nt219-backend`
   - **Region**: `Singapore`
   - **Branch**: `main`
   - **Root Directory**: `.`
   - **Environment**: `Docker`
   - **Dockerfile Path**: `./backend/Dockerfile.render`
   - **Plan**: `Free`

### Bước 3: Cấu hình Environment Variables

Thêm các biến môi trường như ở Phương án 1.

### Bước 4: Deploy

Click **"Create Web Service"** và đợi build hoàn thành.

---

## 🔧 TROUBLESHOOTING

### ❌ Database connection failed

**Nguyên nhân**: Backend không connect được database

**Giải pháp**:
1. Kiểm tra database đã chạy chưa
2. Verify `database_hostname` trong env vars
3. Kiểm tra Internal Connection String của PostgreSQL

### ❌ Health check failed

**Nguyên nhân**: Health check endpoint không trả về 200

**Giải pháp**:
1. Thêm health check endpoint vào backend:

```python
@app.get("/health")
def health_check():
    return {"status": "healthy"}
```

2. Verify Health Check Path trong Render settings: `/health`

### ❌ Port binding error

**Nguyên nhân**: App không bind đúng port

**Giải pháp**: Render tự động set `PORT` env var. Đảm bảo code bind đúng:

```python
# main.py
import os
port = int(os.getenv("PORT", 8000))
```

### ❌ Static files not loading

**Nguyên nhân**: Frontend assets không load

**Giải pháp**: 
1. Deploy frontend riêng như Static Site
2. Hoặc serve qua NGINX trên Render

---

## 📊 MONITORING & LOGS

### Xem Logs

1. Vào service dashboard
2. Click tab **"Logs"**
3. Real-time logs sẽ hiển thị

### Health Checks

Render tự động ping health check endpoint mỗi 30s.

### Metrics

Free plan có basic metrics:
- CPU usage
- Memory usage
- Request count

---

## 💰 COST ESTIMATION

| Service | Plan | Price |
|---------|------|-------|
| PostgreSQL | Free | $0/month (max 1GB) |
| Web Service | Free | $0/month (750hrs) |
| **Total** | | **$0/month** |

**Note**: Free tier có giới hạn:
- Web service sleep sau 15 phút không hoạt động
- Database: 1GB storage
- 750 hours/month runtime

---

## 🔒 SECURITY CHECKLIST

- [ ] Đã set `SECRET_KEY` với giá trị ngẫu nhiên
- [ ] Stripe keys sử dụng **Secret Files** hoặc **Environment Variables**
- [ ] Database password được auto-generate
- [ ] CORS configured với domain cụ thể (không dùng `*`)
- [ ] HTTPS được enable mặc định

---

## 🚀 POST-DEPLOYMENT

### Test API endpoint

```bash
# Health check
curl https://nt219-backend.onrender.com/health

# API test
curl https://nt219-backend.onrender.com/api/products
```

### Update Frontend

Cập nhật API URL trong frontend:

```javascript
const API_BASE_URL = 'https://nt219-backend.onrender.com';
```

### Setup Custom Domain (Optional)

1. Vào service → **Settings** → **Custom Domain**
2. Add CNAME record: `api.yourdomain.com`

---

## 📚 RESOURCES

- [Render Docs](https://render.com/docs)
- [Blueprint Spec](https://render.com/docs/blueprint-spec)
- [Deploy FastAPI](https://render.com/docs/deploy-fastapi)

---

## 🆘 SUPPORT

Nếu gặp vấn đề, check:
1. Render Dashboard logs
2. Build logs
3. Runtime logs
4. Community forum: [community.render.com](https://community.render.com)
