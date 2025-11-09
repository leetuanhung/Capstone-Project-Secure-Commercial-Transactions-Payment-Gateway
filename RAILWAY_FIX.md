# 🚨 RAILWAY FIX - PORT VARIABLE

## Vấn đề:
Railway không tự động inject PORT variable cho tất cả services.

## ✅ GIẢI PHÁP NHANH:

### Bước 1: Set PORT variable trong Railway

1. Railway Dashboard → Click vào **NT219.Q11.ATTN service**
2. Click tab **"Variables"**
3. Click **"New Variable"**
4. Add:
   ```
   Key: PORT
   Value: 8000
   ```
5. Click **"Add"**

### Bước 2: Redeploy

Railway sẽ tự động redeploy sau khi add variable.

---

## 🔄 HOẶC: Dùng hardcoded port

Nếu không muốn set PORT variable, commit thay đổi sau:

```bash
git add entrypoint.sh
git commit -m "Fix PORT handling with fallback"
git push origin main
```

Railway sẽ dùng port 8000 mặc định.

---

## 🌐 Sau khi Active:

1. **Settings** → **Networking** → **Generate Domain**
2. Copy URL và test: `https://your-app.up.railway.app/docs`

