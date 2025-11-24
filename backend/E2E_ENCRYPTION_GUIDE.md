# Client-Side E2E Encryption for Payment Metadata
## Overview
Tài liệu này mô tả **end-to-end encryption** cho metadata thanh toán (cardholder name, device fingerprint) trước khi gửi về backend.

## Kiến trúc hiện tại (ĐÃ AN TOÀN)
```
┌──────────────┐
│ Người dùng   │
│ nhập thẻ     │
└──────┬───────┘
       │ PAN (Primary Account Number)
       ▼
┌─────────────────────────┐
│ Stripe Hosted Fields    │ ← iFrame, domain stripe.com
│ (PCI-DSS compliant)     │
└──────┬──────────────────┘
       │ Token (tok_xxx) - NOT PAN
       ▼
┌─────────────────────────┐
│ Frontend JS             │
│ + HTTPS (TLS 1.3)       │ ← Transport encryption
└──────┬──────────────────┘
       │ POST {token, nonce, name}
       ▼
┌─────────────────────────┐
│ Backend Gateway         │
│ (HMAC + JWT auth)       │
└──────┬──────────────────┘
       │ Stripe API call with token
       ▼
┌─────────────────────────┐
│ Stripe charges card     │
└─────────────────────────┘
```

**Kết luận:** PAN (số thẻ) **không bao giờ** qua server của bạn → PCI DSS SAQ-A ✅

---

## E2E Encryption Layer (Optional Defense-in-Depth)
### Tại sao cần thêm lớp E2E?
- **HTTPS đã bảo vệ transport**, nhưng nếu:
  - TLS bị compromise (MITM với stolen cert - rare)
  - Backend bị hack và attacker đọc được request logs
  - Cần **zero-knowledge architecture** (backend không thấy plaintext metadata)

→ E2E encryption đảm bảo **chỉ backend với private key mới giải mã được**

### Algorithm: Hybrid Encryption (RSA-OAEP + AES-256-GCM)
```
Frontend:
  1. Fetch ephemeral RSA public key từ /api/get_encryption_key
  2. Generate random AES-256 key
  3. Encrypt metadata (cardholder name, fingerprint) với AES-GCM
  4. Encrypt AES key với RSA public key
  5. Send {encryptedData, encryptedKey, iv} to backend

Backend:
  1. Decrypt AES key với RSA private key (in-memory, ephemeral)
  2. Decrypt metadata với AES key
  3. Process payment
  4. Rotate RSA key mỗi 1 giờ
```

---

## Sử dụng (Implementation Guide)

### 1. Backend: Thêm endpoint cung cấp public key
File: `backend/services/payment_service/security/crypto_provider.py` (đã tạo)

Thêm route vào `backend/gateway/main.py`:
```python
from backend.services.payment_service.security.crypto_provider import router as crypto_router

app.include_router(crypto_router, prefix="/api", tags=["crypto"])
```

### 2. Frontend: Load crypto utility
Trong `checkout.html`, thêm trước `</head>`:
```html
<script src="/static/js/crypto_utils.js"></script>
```

### 3. Modify payment form submission
Replace phần tạo formData trong `checkout.html`:
```javascript
// OLD (hiện tại):
const formData = new FormData(form);

// NEW (với E2E encryption):
const cardholderName = document.getElementById('card-holder-name').value;
const deviceFingerprint = window.PaymentCrypto.generateDeviceFingerprint();

// Encrypt metadata
const encryptedName = await window.PaymentCrypto.encryptMetadata(cardholderName);
const encryptedFingerprint = await window.PaymentCrypto.encryptMetadata(deviceFingerprint);

// Build form data with encrypted fields
const formData = new FormData();
formData.append('order_id', document.getElementById('order-id').value);
formData.append('payment_token', token.id);
formData.append('nonce', nonce);
formData.append('encrypted_cardholder_name', JSON.stringify(encryptedName));
formData.append('encrypted_device_fingerprint', JSON.stringify(encryptedFingerprint));
```

### 4. Backend: Decrypt trong payment route
File: `backend/services/payment_service/payment.py`

```python
from .security.crypto_provider import decrypt_metadata
import json

@router.post("/create_payment")
async def create_payment(
    request: Request,
    order_id: str = Form(...),
    payment_token: str = Form(...),
    encrypted_cardholder_name: str = Form(...),
    encrypted_device_fingerprint: str = Form(...),
    ...
):
    # Decrypt metadata
    encrypted_name_obj = json.loads(encrypted_cardholder_name)
    cardholder_name = decrypt_metadata(
        encrypted_name_obj["encryptedData"],
        encrypted_name_obj["encryptedKey"],
        encrypted_name_obj["iv"]
    )
    
    encrypted_fp_obj = json.loads(encrypted_device_fingerprint)
    device_fingerprint = decrypt_metadata(
        encrypted_fp_obj["encryptedData"],
        encrypted_fp_obj["encryptedKey"],
        encrypted_fp_obj["iv"]
    )
    
    # Continue with payment processing...
```

---

## Security Considerations

### ✅ Đã implement:
- Stripe Hosted Fields (PCI-DSS scope reduction)
- Tokenization (PAN → token)
- HTTPS/TLS 1.3 transport
- HMAC request signing
- JWT authentication
- Nonce anti-replay
- Device fingerprinting

### ⚠️ Optional improvements (E2E encryption):
- Ephemeral RSA key rotation (1 giờ)
- Hybrid encryption (RSA + AES-GCM)
- Zero-knowledge metadata (backend không log plaintext)

### 🔒 Production checklist:
- [ ] Private key lưu trong HSM/KMS (không hard-code)
- [ ] Rate limit `/api/get_encryption_key` endpoint
- [ ] Monitor key rotation failures
- [ ] Audit logs (encrypted) cho payment events
- [ ] CSP header để chặn XSS
- [ ] Subresource Integrity (SRI) cho Stripe JS SDK

---

## Testing

### Test E2E encryption locally:
```bash
# 1. Start backend
uvicorn backend.gateway.main:app --reload

# 2. Open browser console on checkout page
# 3. Test encryption:
const crypto = window.PaymentCrypto;
await crypto.fetchPublicKey();
const encrypted = await crypto.encryptMetadata("NGUYEN VAN A");
console.log(encrypted); // Should show {encryptedData, encryptedKey, iv}
```

### Test với curl (simulate frontend):
```bash
# Get public key
curl http://localhost:8000/api/get_encryption_key

# Manual encryption test (need to implement client)
# Or use Python script to simulate
```

---

## Performance Impact
- **Ephemeral key generation:** ~50ms (1 giờ mới rotate 1 lần)
- **RSA encryption (2048-bit):** ~1-2ms per field
- **AES-GCM encryption:** <0.5ms
- **Total overhead:** ~3-5ms (negligible so với Stripe API latency ~200-500ms)

---

## Kết luận
- **Hiện tại:** Đã an toàn theo PCI-DSS (Stripe Hosted Fields + Tokenization + HTTPS)
- **E2E encryption:** Optional layer for defense-in-depth và zero-knowledge architecture
- **Khuyến nghị:** Implement nếu:
  - Compliance yêu cầu (GDPR, HIPAA)
  - Muốn audit-proof (không log plaintext metadata)
  - Multi-region deployment (giảm trust boundary)

**Không implement nếu:**
- Team nhỏ, chưa có HSM/KMS infrastructure
- Chỉ cần PCI-DSS compliance (đã đủ với Stripe Hosted Fields)
- Ưu tiên time-to-market hơn defense-in-depth
