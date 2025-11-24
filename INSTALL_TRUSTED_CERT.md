# 🔒 Cài đặt Trusted Certificate (Loại bỏ cảnh báo browser)

## Tại sao cần?
- Certificate hiện tại là **self-signed** → Browser cảnh báo `NET::ERR_CERT_AUTHORITY_INVALID`
- Để loại bỏ cảnh báo, cần trust certificate hoặc dùng mkcert

---

## ✅ Option 1: Trust Self-Signed Certificate (Nhanh)

### Windows
```powershell
# Mở PowerShell với quyền Administrator
certutil -addstore "Root" backend\certs\localhost.crt

# Verify
certutil -store Root | Select-String "localhost"
```

### Sau khi import:
1. Restart browser (đóng hẳn và mở lại)
2. Truy cập https://localhost:8000
3. ✅ Không còn cảnh báo

### Gỡ bỏ certificate (khi không cần nữa):
```powershell
# Mở certmgr.msc → Trusted Root Certification Authorities → Certificates
# Tìm "localhost" → Right-click → Delete
```

---

## ✅ Option 2: Dùng mkcert (Recommended)

### Cài đặt mkcert
```powershell
# Dùng Chocolatey
choco install mkcert -y

# Hoặc dùng Scoop
scoop bucket add extras
scoop install mkcert
```

### Tạo trusted certificate
```powershell
# Install root CA
mkcert -install

# Tạo certificate cho localhost
cd backend\certs
mkcert -key-file localhost.key -cert-file localhost.crt localhost 127.0.0.1 ::1

# Backup certificate cũ
Move-Item localhost.crt localhost.crt.old -Force
Move-Item localhost.key localhost.key.old -Force
```

### Restart server
```powershell
python backend\run_https.py
```

### Kết quả:
- ✅ Browser hiện 🔒 màu xanh (Secure)
- ✅ Không cảnh báo
- ✅ Certificate được CA local trust

---

## ❌ Option 3: Bypass mỗi lần (Không cần install)

### Chrome/Edge:
1. Thấy cảnh báo → Gõ `thisisunsafe` (không cần click)
2. Hoặc: Click **Advanced** → **Proceed to 127.0.0.1**

### Firefox:
- Click **Advanced** → **Accept the Risk and Continue**

---

## 🌐 Production: Dùng Let's Encrypt

Khi deploy lên server thật:

```bash
# Cài Certbot
sudo apt install certbot python3-certbot-nginx

# Tạo certificate (miễn phí, trusted by all browsers)
sudo certbot --nginx -d yourdomain.com

# Auto-renew
sudo certbot renew --dry-run
```

---

## 📋 So sánh

| Method | Pros | Cons | Use Case |
|--------|------|------|----------|
| **Bypass** | Nhanh, không cần install | Phải bypass mỗi lần | Quick testing |
| **Trust self-signed** | Permanent fix | Certificate tự ký vẫn không professional | Local dev |
| **mkcert** | Trusted CA, professional | Cần install tool | Team development |
| **Let's Encrypt** | Public trusted, miễn phí | Chỉ cho domain thật | Production |

---

## ⚡ Quick Start (Recommended)

```powershell
# Trust certificate ngay (Admin PowerShell)
certutil -addstore "Root" backend\certs\localhost.crt

# Restart browser
# Truy cập: https://localhost:8000
# → ✅ Không còn cảnh báo!
```
