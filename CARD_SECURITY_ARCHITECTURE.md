# Card Data Security Architecture
## Current Implementation (SECURE ✅)

```
╔════════════════════════════════════════════════════════════════════╗
║                    CARD DATA SECURITY LAYERS                        ║
╚════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────┐
│ LAYER 1: PCI-DSS Scope Reduction (Stripe Hosted Fields)            │
└─────────────────────────────────────────────────────────────────────┘

    [User Browser]
         │
         │ User nhập: 4242 4242 4242 4242
         ▼
    ┌──────────────────────────┐
    │  Stripe iFrame           │ ← Chạy trên domain stripe.com
    │  (Isolated Sandbox)      │   KHÔNG access được bởi JS của bạn
    │                          │
    │  Input: PAN, CVV, Expiry │
    │  Output: tok_xxxxxxxxxx  │ ← One-time token
    └──────────┬───────────────┘
               │
               │ Token ONLY (không phải PAN)
               ▼
    ┌──────────────────────────┐
    │  Frontend JavaScript     │
    │  (Bạn không thấy PAN)    │ ← PCI-DSS SAQ-A compliance
    └──────────┬───────────────┘
               │
               
┌──────────────┴──────────────────────────────────────────────────────┐
│ LAYER 2: Transport Security (HTTPS/TLS 1.3)                         │
└──────────────────────────────────────────────────────────────────────┘

    POST /payment_service/create_payment
    Content: {
        payment_token: "tok_xxxxxxxxxx",  ← Stripe token (NOT PAN)
        nonce: "uuid-v4",                 ← Anti-replay
        device_fingerprint: "base64..."   ← Fraud detection
    }
         │
         │ TLS 1.3 encrypted (AES-256-GCM)
         ▼
    ┌──────────────────────────┐
    │  Backend Gateway         │
    │  + HMAC signature verify │ ← Request integrity
    │  + JWT auth              │ ← User authentication
    │  + Rate limiting         │ ← Anti-abuse
    └──────────┬───────────────┘
               │
               
┌──────────────┴──────────────────────────────────────────────────────┐
│ LAYER 3: Payment Processing (Tokenization)                          │
└──────────────────────────────────────────────────────────────────────┘

    ┌──────────────────────────┐
    │  Payment Service         │
    │                          │
    │  1. Fraud Detection      │ ← Rule engine + ML score
    │  2. Stripe API call      │ ← PaymentIntent.create(token)
    │  3. Receipt signing      │ ← HSM/PKCS#11
    └──────────┬───────────────┘
               │
               │ HTTPS API call với token
               ▼
    ┌──────────────────────────┐
    │  Stripe Backend          │
    │                          │
    │  - Detokenize token      │ ← tok_xxx → 4242 4242 4242 4242
    │  - Charge card           │
    │  - Return PaymentIntent  │
    └──────────────────────────┘


╔════════════════════════════════════════════════════════════════════╗
║  KEY SECURITY POINTS                                                ║
╚════════════════════════════════════════════════════════════════════╝

✅ PAN (số thẻ) NEVER qua server của bạn
   → Scope: PCI-DSS SAQ-A (self-assessment only)

✅ Tokenization tại client
   → Backend chỉ thấy token, không thấy plaintext card

✅ HTTPS/TLS 1.3
   → Transport encryption (AES-256-GCM)

✅ HMAC request signing
   → Request integrity + anti-tampering

✅ Nonce (UUID)
   → Prevent replay attacks

✅ Device fingerprinting
   → Fraud detection + account takeover prevention


╔════════════════════════════════════════════════════════════════════╗
║  OPTIONAL: E2E Encryption Layer (Defense-in-Depth)                 ║
╚════════════════════════════════════════════════════════════════════╝

Nếu muốn thêm lớp mã hóa end-to-end cho metadata:

    [Frontend]
         │
         │ Cardholder Name: "NGUYEN VAN A"
         ▼
    ┌──────────────────────────┐
    │  Web Crypto API          │
    │  (AES-256-GCM + RSA)     │
    │                          │
    │  1. Generate AES key     │ ← Random 256-bit
    │  2. Encrypt metadata     │ ← AES-GCM
    │  3. Encrypt AES key      │ ← RSA-2048 public key
    └──────────┬───────────────┘
               │
               │ {encryptedData, encryptedKey, iv}
               ▼
    ┌──────────────────────────┐
    │  Backend Gateway         │
    │                          │
    │  1. Decrypt AES key      │ ← RSA-2048 private key (ephemeral)
    │  2. Decrypt metadata     │ ← AES-GCM
    │  3. Process payment      │
    └──────────────────────────┘

Lợi ích:
  - Zero-knowledge: Backend không log plaintext metadata
  - MITM protection: Ngay cả khi TLS bị compromise
  - Compliance: GDPR, HIPAA requirements

Chi phí:
  - Complexity tăng
  - Cần manage ephemeral key rotation
  - ~3-5ms latency overhead


╔════════════════════════════════════════════════════════════════════╗
║  THREAT MODEL & MITIGATIONS                                         ║
╚════════════════════════════════════════════════════════════════════╝

┌──────────────────────────────┬─────────────────────────────────────┐
│ THREAT                       │ MITIGATION                          │
├──────────────────────────────┼─────────────────────────────────────┤
│ Attacker sniff card data     │ ✅ Stripe Hosted Fields (iFrame)   │
│ từ frontend JS               │    PAN never in DOM                 │
├──────────────────────────────┼─────────────────────────────────────┤
│ MITM attack (network tap)    │ ✅ TLS 1.3 + HSTS                  │
│                              │ ✅ Optional: E2E encryption         │
├──────────────────────────────┼─────────────────────────────────────┤
│ Backend database breach      │ ✅ No PAN stored                   │
│ (attacker đọc DB)            │ ✅ Tokens are one-time use         │
├──────────────────────────────┼─────────────────────────────────────┤
│ Replay attack                │ ✅ Nonce (UUID) checked            │
│ (gửi lại request cũ)         │ ✅ Token expire sau 5 phút         │
├──────────────────────────────┼─────────────────────────────────────┤
│ Request tampering            │ ✅ HMAC signature verification     │
│ (sửa amount, order_id)       │ ✅ JWT user authentication         │
├──────────────────────────────┼─────────────────────────────────────┤
│ Fraud (stolen card)          │ ✅ Fraud detection module          │
│                              │    - High-value transaction rules   │
│                              │    - High-risk country check        │
│                              │    - ML scoring (placeholder)       │
├──────────────────────────────┼─────────────────────────────────────┤
│ XSS (inject malicious JS)    │ ⚠️  TODO: CSP header               │
│                              │ ⚠️  TODO: SRI for Stripe SDK       │
├──────────────────────────────┼─────────────────────────────────────┤
│ Credential stuffing          │ ⚠️  TODO: 2FA                      │
│ (password reuse attacks)     │ ⚠️  TODO: Device binding           │
└──────────────────────────────┴─────────────────────────────────────┘


╔════════════════════════════════════════════════════════════════════╗
║  COMPLIANCE STATUS                                                  ║
╚════════════════════════════════════════════════════════════════════╝

PCI-DSS:
  ✅ SAQ-A (simplified compliance)
  ✅ No cardholder data storage
  ✅ TLS for data in transit
  ⚠️  TODO: Quarterly ASV scan
  ⚠️  TODO: Annual self-assessment

GDPR:
  ✅ Data minimization (no PAN storage)
  ✅ Encryption at rest (field-level)
  ⚠️  TODO: Right to erasure implementation
  ⚠️  TODO: Data processing agreement with Stripe

OWASP Top 10:
  ✅ A02: Cryptographic Failures → TLS + tokenization
  ✅ A04: Insecure Design → Defense in depth
  ✅ A07: Identification/Auth → JWT + HMAC
  ⚠️  A03: Injection → TODO: Input validation
  ⚠️  A05: Security Misconfiguration → TODO: CSP
```
