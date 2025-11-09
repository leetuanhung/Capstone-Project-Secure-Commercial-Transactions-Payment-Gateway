# 🚀 Quick Setup Guide

## Bước 1: Tạo file `.env`

**Windows:**
```powershell
Copy-Item .env.example .env
```

**Linux/Mac:**
```bash
cp .env.example .env
```

## Bước 2: Sinh AES Key (BẮT BUỘC!)

Chạy lệnh:

**Windows (PowerShell):**
```powershell
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

**Linux/Mac:**
```bash
python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

**Output ví dụ:**
```
yAJCYEC/1yTdfgnBlSKXk5F84gyS03LJRSrW20+zLGg=
```

Mở file `.env` và thay thế:
```properties
Key_AES=yAJCYEC/1yTdfgnBlSKXk5F84gyS03LJRSrW20+zLGg=
USER_AES_KEY=yAJCYEC/1yTdfgnBlSKXk5F84gyS03LJRSrW20+zLGg=
```

## Bước 3: Tùy chỉnh database (nếu muốn)

Trong file `.env`, đổi:
```properties
database_password=your_password
database_name=your_database_name
database_username=your_username
```

## Bước 4: Chạy Docker

```bash
docker compose up --build
```

Truy cập: http://localhost:8000

---

## ❌ Lỗi thường gặp

### "USER_AES_KEY environment variable is required"
→ Chưa sinh AES key (xem Bước 2)

### "Cannot connect to database"
```bash
docker compose down -v
docker compose up --build
```

### "Port already in use"
```bash
# Đổi port trong docker-compose.yml hoặc stop service đang dùng port
```

---

## 📋 Checklist

- [ ] Copy `.env.example` → `.env`
- [ ] Sinh AES key bằng lệnh Python
- [ ] Cập nhật `Key_AES` và `USER_AES_KEY` trong `.env`
- [ ] (Optional) Đổi database password
- [ ] Chạy `docker compose up --build`
- [ ] Mở http://localhost:8000

✅ Done!
