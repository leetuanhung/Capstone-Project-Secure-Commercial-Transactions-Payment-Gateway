# 🚀 Railway Environment Variables Setup

## ⚠️ **VẤN ĐỀ HIỆN TẠI**
App đã deploy thành công nhưng **thiếu environment variables**, dẫn đến lỗi:
```
pydantic_core._pydantic_core.ValidationError: 11 validation errors for Settings
```

## ✅ **GIẢI PHÁP: SET BIẾN MÔI TRƯỜNG TRÊN RAILWAY**

### 📋 **Bước 1: Mở Railway Dashboard**
1. Truy cập: https://railway.app/dashboard
2. Click vào project của bạn
3. Click vào **service** (container đang chạy)
4. Click tab **Variables**

---

### 🔐 **Bước 2: Thêm Database Variables (Railway tự động inject)**

Railway đã tạo PostgreSQL database, bạn cần link nó với app:

#### **Option 1: Dùng Railway Reference Variables (Khuyến nghị)**
Thêm các biến sau (Railway sẽ tự động fill giá trị từ Postgres service):

```bash
database_hostname=${{Postgres.RAILWAY_PRIVATE_DOMAIN}}
database_port=5432
database_password=${{Postgres.PGPASSWORD}}
database_name=${{Postgres.PGDATABASE}}
database_username=${{Postgres.PGUSER}}
```

#### **Option 2: Copy từ Postgres Service (Thủ công)**
1. Click vào **Postgres service** (database container)
2. Vào tab **Variables**
3. Copy các giá trị:
   - `PGHOST` → dùng cho `database_hostname`
   - `PGPORT` → dùng cho `database_port`
   - `PGPASSWORD` → dùng cho `database_password`
   - `PGDATABASE` → dùng cho `database_name`
   - `PGUSER` → dùng cho `database_username`

---

### 🔑 **Bước 3: Thêm Security Keys (BẮT BUỘC)**

Dùng các key đã generate từ trước (trong file `generate_keys.py`):

```bash
# JWT Authentication
secret_key=CYnHBgY5abSeml0mkf2beRjSY3-Hd3TPyFa-bDVQVA_HVs0LyzKFS-RQlxwW1fgPTiM7fZOjqCsOfeIcaZUImQ
algorithm=HS256
access_token_expire_minutes=60

# AES Encryption Keys
Key_AES=v0s5B4o7P2xlq/+FuBvzMFW3PgXwSLcbCU9Qij/Rd9M=
USER_AES_KEY=3zIlt4Oho8qothN6Sf7OXS1qSFZuGIjvRkuTiIdpbeA=
```

---

### 💳 **Bước 4: Thêm Stripe Keys (TÙY CHỌN - nếu dùng payment)**

Nếu bạn muốn test payment, lấy test keys từ Stripe:
1. Truy cập: https://dashboard.stripe.com/test/apikeys
2. Copy **Publishable key** và **Secret key**

```bash
Stripe_Public_Key=pk_test_YOUR_STRIPE_PUBLIC_KEY
Stripe_Secret_Key=sk_test_YOUR_STRIPE_SECRET_KEY
```

⚠️ **Nếu không dùng Stripe ngay:** Để giá trị dummy để tránh lỗi:
```bash
Stripe_Public_Key=pk_test_dummy_key_for_testing
Stripe_Secret_Key=sk_test_dummy_key_for_testing
```

---

## 📝 **DANH SÁCH ĐẦY ĐỦ CÁC BIẾN CẦN THÊM**

Copy toàn bộ block này vào Railway Variables (chọn **Raw Editor**):

```bash
# Database (dùng Railway references)
database_hostname=${{Postgres.RAILWAY_PRIVATE_DOMAIN}}
database_port=5432
database_password=${{Postgres.PGPASSWORD}}
database_name=${{Postgres.PGDATABASE}}
database_username=${{Postgres.PGUSER}}

# JWT Authentication
secret_key=CYnHBgY5abSeml0mkf2beRjSY3-Hd3TPyFa-bDVQVA_HVs0LyzKFS-RQlxwW1fgPTiM7fZOjqCsOfeIcaZUImQ
algorithm=HS256
access_token_expire_minutes=60

# AES Encryption
Key_AES=v0s5B4o7P2xlq/+FuBvzMFW3PgXwSLcbCU9Qij/Rd9M=
USER_AES_KEY=3zIlt4Oho8qothN6Sf7OXS1qSFZuGIjvRkuTiIdpbeA=

# Stripe (dummy values - thay bằng real keys nếu cần)
Stripe_Public_Key=pk_test_dummy_key_for_testing
Stripe_Secret_Key=sk_test_dummy_key_for_testing
```

---

## 🎯 **Bước 5: Redeploy**

Sau khi thêm variables:
1. Railway sẽ **tự động redeploy** (hoặc click **Redeploy** manually)
2. Đợi ~30-60 giây để container restart
3. Check **Logs** để xác nhận không còn lỗi Pydantic

---

## ✅ **KIỂM TRA KẾT QUẢ**

### **Logs thành công sẽ hiển thị:**
```
Starting uvicorn on port 8080...
INFO:     Started server process [1]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8080 (Press CTRL+C to quit)
```

### **Không còn lỗi:**
- ❌ `Field required [type=missing, input_value={}, input_type=dict]`
- ✅ App running successfully

---

## 🌐 **Bước 6: Generate Domain và Test**

Sau khi deployment thành công:

1. **Generate Domain:**
   - Settings → Networking → **Generate Domain**
   - Railway sẽ tạo URL: `https://your-app.up.railway.app`

2. **Test Endpoints:**
   ```bash
   # Health check
   curl https://your-app.up.railway.app/
   
   # API docs
   https://your-app.up.railway.app/docs
   ```

---

## 🆘 **TROUBLESHOOTING**

### **Lỗi: "database_hostname Field required"**
✅ **Fix:** Kiểm tra Railway có **Postgres service** chưa:
- Dashboard → Add Service → Database → PostgreSQL
- Sau đó dùng reference variables: `${{Postgres.RAILWAY_PRIVATE_DOMAIN}}`

### **Lỗi: "Can't connect to Postgres"**
✅ **Fix:** Đảm bảo cả 2 services (App + Postgres) cùng trong 1 project
- Postgres phải ở trạng thái **Active**
- App service phải có variables reference đến Postgres

### **Lỗi: "secret_key Field required"**
✅ **Fix:** Copy đúng tên biến (lowercase, underscore)
- ❌ Sai: `SECRET_KEY=xxx`
- ✅ Đúng: `secret_key=xxx`

---

## 📚 **TÀI LIỆU THAM KHẢO**

- Railway Variables: https://docs.railway.app/guides/variables
- Postgres on Railway: https://docs.railway.app/databases/postgresql
- Reference Variables: https://docs.railway.app/guides/variables#reference-variables

---

## 💡 **LƯU Ý BẢO MẬT**

⚠️ **QUAN TRỌNG:**
- **KHÔNG** commit file `.env` lên GitHub
- Chỉ commit `.env.example` (template không có giá trị thật)
- Keys đã generate chỉ dùng cho **production Railway**, không dùng local development
- Regenerate keys định kỳ (3-6 tháng)

---

🎉 **Sau khi hoàn thành tất cả bước trên, app sẽ chạy hoàn hảo trên Railway!**
