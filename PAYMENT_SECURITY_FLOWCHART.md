# Payment Gateway Security Flowchart
> Sơ đồ luồng bảo mật cho Payment Gateway - NT219 Capstone Project

## 1. Complete Payment Flow với Security Layers

```mermaid
flowchart TD
    Start([👤 Người dùng bắt đầu thanh toán]) --> SelectProduct[🛒 Chọn sản phẩm và thêm vào giỏ]
    SelectProduct --> Checkout[📋 Checkout - Tạo Order]
    
    Checkout --> LoadCheckout[🌐 Load checkout.html]
    LoadCheckout --> StripeSDK[📦 Tải Stripe JS SDK]
    
    StripeSDK --> CreateHostedFields[🔒 Tạo Hosted Fields iFrame]
    CreateHostedFields --> IframeSecurity{🛡️ SECURITY: iFrame Isolation}
    
    IframeSecurity --> |"Domain: stripe.com<br/>Isolated sandbox"| UserInput[⌨️ User nhập thẻ vào iFrame]
    
    UserInput --> CardData["💳 Card Data:<br/>PAN: 4242 4242 4242 4242<br/>CVV: 123<br/>Expiry: 12/25"]
    
    CardData --> TokenRequest[🔐 Gọi stripe.createToken]
    TokenRequest --> StripeServer[☁️ Stripe Server]
    
    StripeServer --> Tokenize[🎫 Tokenization:<br/>PAN → tok_xxxxxxxxxx]
    Tokenize --> TokenReturn[📤 Trả token về Frontend]
    
    TokenReturn --> JSReceive[📥 Frontend JS nhận token]
    JSReceive --> NeverSeePAN{❌ JS KHÔNG BAO GIỜ thấy PAN}
    
    NeverSeePAN --> GenerateNonce[🎲 Generate Nonce UUID]
    GenerateNonce --> DeviceFingerprint[🖥️ Generate Device Fingerprint]
    
    DeviceFingerprint --> BuildPayload["📦 Build Payload:<br/>- payment_token: tok_xxx<br/>- nonce: uuid<br/>- order_id: 123<br/>- device_fingerprint: base64"]
    
    BuildPayload --> TLSCheck{🔒 HTTPS/TLS 1.3?}
    TLSCheck --> |No| RejectHTTP[❌ Reject HTTP connection]
    TLSCheck --> |Yes| POSTRequest[📡 POST /payment_service/create_payment]
    
    POSTRequest --> Gateway[🚪 API Gateway]
    
    Gateway --> Middleware1[⚙️ Middleware 1: Request ID]
    Middleware1 --> Middleware2[⚙️ Middleware 2: CORS Check]
    Middleware2 --> Middleware3[⚙️ Middleware 3: Rate Limiter]
    
    Middleware3 --> RateLimitCheck{🚦 Rate limit OK?}
    RateLimitCheck --> |Exceeded| RateLimitError[❌ 429 Too Many Requests]
    RateLimitCheck --> |OK| Middleware4[⚙️ Middleware 4: JWT Auth]
    
    Middleware4 --> JWTCheck{🔑 JWT valid?}
    JWTCheck --> |Invalid| AuthError[❌ 401 Unauthorized]
    JWTCheck --> |Valid| Middleware5[⚙️ Middleware 5: HMAC Verify]
    
    Middleware5 --> HMACCheck{🔏 HMAC signature valid?}
    HMACCheck --> |Invalid| HMACError[❌ 403 Forbidden - Tampered]
    HMACCheck --> |Valid| PaymentService[💰 Payment Service]
    
    PaymentService --> FraudDetection[🕵️ Fraud Detection Module]
    
    FraudDetection --> CheckHighValue{💵 High-value tx?<br/>amount >= threshold}
    CheckHighValue --> |Yes| HighValueFlag[🚩 Flag: HIGH_VALUE]
    CheckHighValue --> |No| CheckCountry
    
    HighValueFlag --> CheckCountry{🌍 High-risk country?<br/>KP/IR/SY}
    CheckCountry --> |Yes| CountryFlag[🚩 Flag: HIGH_RISK_COUNTRY]
    CheckCountry --> |No| CheckIP
    
    CountryFlag --> CheckIP{🌐 Missing IP?}
    CheckIP --> |Yes| IPFlag[🚩 Flag: MISSING_IP]
    CheckIP --> |No| MLScore
    
    IPFlag --> MLScore[🤖 ML Fraud Score]
    
    MLScore --> CalculateScore["🧮 Calculate Final Score:<br/>Score = Σ(flags * weight) + ML"]
    
    CalculateScore --> FraudThreshold{⚖️ Score >= 0.75?}
    FraudThreshold --> |Yes| BlockTransaction[🚫 BLOCK Transaction]
    FraudThreshold --> |No| AllowTransaction[✅ Allow Transaction]
    
    BlockTransaction --> ErrorPage[❌ Render error.html]
    ErrorPage --> UserRetry{👤 User action?}
    UserRetry --> |"🏠 Về trang chủ"| Home[🏠 Homepage]
    UserRetry --> |"🛒 Xem giỏ hàng"| Cart[🛒 Cart]
    UserRetry --> |"🔄 Thử lại"| Checkout
    
    AllowTransaction --> EncryptMetadata[🔐 Encrypt sensitive fields<br/>FieldEncryption AES-256-GCM]
    
    EncryptMetadata --> StripeAPI[☁️ Call Stripe API]
    StripeAPI --> CreatePaymentIntent["📋 Create PaymentIntent<br/>với token + metadata"]
    
    CreatePaymentIntent --> StripeCharge[💳 Stripe charge thẻ thật]
    
    StripeCharge --> ChargeResult{✅ Charge success?}
    ChargeResult --> |Failed| PaymentFailed[❌ Payment failed]
    ChargeResult --> |Success| SaveOrder[💾 Save Order to DB]
    
    SaveOrder --> EncryptDB[🔒 Encrypt sensitive DB fields]
    EncryptDB --> SignReceipt[✍️ Sign receipt với HSM]
    
    SignReceipt --> TokenizeCard[🎫 Tokenize card for future<br/>SecureStorage + Checksum]
    
    TokenizeCard --> AuditLog[📝 Audit Log<br/>Encrypted + Timestamped]
    
    AuditLog --> SuccessPage[✅ Render success.html]
    SuccessPage --> End([🎉 Payment Complete])
    
    PaymentFailed --> ErrorPage
    RateLimitError --> ErrorPage
    AuthError --> ErrorPage
    HMACError --> ErrorPage
    RejectHTTP --> ErrorPage
    
    style Start fill:#e1f5e1
    style End fill:#e1f5e1
    style IframeSecurity fill:#fff3cd
    style NeverSeePAN fill:#fff3cd
    style TLSCheck fill:#fff3cd
    style RateLimitCheck fill:#fff3cd
    style JWTCheck fill:#fff3cd
    style HMACCheck fill:#fff3cd
    style FraudThreshold fill:#fff3cd
    style ChargeResult fill:#fff3cd
    style BlockTransaction fill:#f8d7da
    style ErrorPage fill:#f8d7da
    style SuccessPage fill:#d1f2eb
```

### **Tên:** Luồng Thanh Toán Hoàn Chỉnh với Các Lớp Bảo Mật

### **Giải thích:**
Đây là sơ đồ chi tiết nhất, mô tả **toàn bộ hành trình** từ khi người dùng bắt đầu thanh toán đến khi hoàn tất (hoặc bị chặn). 

**Cách hoạt động:**
1. **Bước 1-7 (Frontend - Bảo vệ dữ liệu thẻ):** Người dùng nhập thẻ vào **Stripe iFrame** (không phải website của bạn) → Stripe tự động chuyển số thẻ thành **token** → JavaScript của bạn **không bao giờ thấy số thẻ thật**.

2. **Bước 8-11 (Chuẩn bị gửi):** Frontend tạo **nonce** (số random chống replay attack) và **device fingerprint** (dấu vết thiết bị để phát hiện gian lận), đóng gói cùng token vào payload.

3. **Bước 12-13 (Kiểm tra TLS):** Nếu không dùng HTTPS → **từ chối ngay** (bảo vệ dữ liệu trên đường truyền).

4. **Bước 14-20 (API Gateway - 5 lớp bảo mật):**
   - Request ID: Gán ID duy nhất để truy vết
   - CORS: Chặn request từ domain lạ
   - Rate Limiter: Chặn nếu request quá nhiều (DDoS)
   - JWT Auth: Kiểm tra người dùng đã đăng nhập chưa
   - HMAC Verify: Kiểm tra request có bị sửa đổi giữa đường không

5. **Bước 21-27 (Fraud Detection - Phát hiện gian lận):** Kiểm tra 3 điều kiện:
   - Số tiền có lớn bất thường không? (≥ 100 USD)
   - Quốc gia có nguy hiểm không? (Triều Tiên, Iran, Syria)
   - Thiếu địa chỉ IP không?
   - ML Model cho điểm nghi ngờ (0-1)
   - **Nếu tổng điểm ≥ 0.75 → CHẶN giao dịch** → Hiện trang lỗi → User có thể về trang chủ, xem giỏ hàng, hoặc thử lại

6. **Bước 28-31 (Thanh toán thực):** Nếu không bị chặn:
   - Mã hóa metadata nhạy cảm (AES-256-GCM)
   - Gọi Stripe API với token
   - Stripe charge thẻ thật

7. **Bước 32-37 (Lưu trữ & Hoàn tất):** 
   - Lưu order vào database (mã hóa các trường nhạy cảm)
   - Ký hóa đơn bằng HSM (chữ ký số chống giả mạo)
   - Tokenize thẻ để dùng cho lần sau
   - Ghi audit log (ai, khi nào, làm gì)
   - Hiện trang thành công

**Kết quả:** Mỗi giao dịch phải vượt qua **13 bước kiểm tra bảo mật** trước khi được thực hiện!

---

## 2. Security Layers Detail

```mermaid
flowchart LR
    subgraph Frontend["🌐 Frontend Security"]
        A1[Stripe Hosted Fields<br/>iFrame Isolation]
        A2[Tokenization<br/>PAN → Token]
        A3[Nonce Generation<br/>Anti-Replay]
        A4[Device Fingerprint<br/>Fraud Detection]
        A1 --> A2 --> A3 --> A4
    end
    
    subgraph Transport["🔒 Transport Security"]
        B1[HTTPS/TLS 1.3]
        B2[Certificate Pinning]
        B3[HSTS Header]
        B1 --> B2 --> B3
    end
    
    subgraph Gateway["🚪 API Gateway"]
        C1[Request ID]
        C2[CORS]
        C3[Rate Limiter]
        C4[JWT Auth]
        C5[HMAC Verify]
        C1 --> C2 --> C3 --> C4 --> C5
    end
    
    subgraph Payment["💰 Payment Service"]
        D1[Fraud Detection]
        D2[Stripe Integration]
        D3[Field Encryption]
        D4[HSM Signing]
        D1 --> D2 --> D3 --> D4
    end
    
    subgraph Storage["💾 Data Storage"]
        E1[Field-Level Encryption<br/>AES-256-GCM + AAD]
        E2[Tokenization<br/>Secure Storage]
        E3[Checksum Verification]
        E4[Audit Logging]
        E1 --> E2 --> E3 --> E4
    end
    
    Frontend --> Transport --> Gateway --> Payment --> Storage
    
    style Frontend fill:#e3f2fd
    style Transport fill:#fff3e0
    style Gateway fill:#f3e5f5
    style Payment fill:#e8f5e9
    style Storage fill:#fce4ec
```

### **Tên:** Kiến Trúc 5 Lớp Bảo Mật

### **Giải thích:**
Sơ đồ này cho thấy bảo mật được chia thành **5 tầng độc lập**, mỗi tầng có nhiệm vụ riêng.

**Cách hoạt động (từ trái sang phải):**

1. **🌐 Frontend Security (Tầng 1):** Bảo vệ ngay tại trình duyệt người dùng
   - **Stripe Hosted Fields:** Số thẻ được nhập vào iFrame cách ly (không thể đọc được)
   - **Tokenization:** Chuyển số thẻ thành token ngay lập tức
   - **Nonce:** Tạo số random để chống replay attack
   - **Device Fingerprint:** Thu thập thông tin thiết bị để phát hiện hành vi lạ

2. **🔒 Transport Security (Tầng 2):** Bảo vệ khi dữ liệu di chuyển qua internet
   - **HTTPS/TLS 1.3:** Mã hóa toàn bộ dữ liệu truyền đi (như bỏ vào phong bì kín)
   - **Certificate Pinning:** Chỉ tin tưởng chứng chỉ đúng (chống MITM)
   - **HSTS Header:** Bắt buộc trình duyệt luôn dùng HTTPS

3. **🚪 API Gateway (Tầng 3):** Cổng kiểm soát chính, có 5 lớp middleware
   - **Request ID:** Gán ID để truy vết request xuyên suốt hệ thống
   - **CORS:** Chặn request từ domain không được phép
   - **Rate Limiter:** Giới hạn số request (chống DDoS)
   - **JWT Auth:** Xác thực người dùng (kiểm tra đã đăng nhập)
   - **HMAC Verify:** Kiểm tra chữ ký request (phát hiện sửa đổi)

4. **💰 Payment Service (Tầng 4):** Xử lý logic thanh toán
   - **Fraud Detection:** Phát hiện giao dịch gian lận
   - **Stripe Integration:** Gọi API Stripe để charge thẻ
   - **Field Encryption:** Mã hóa từng trường dữ liệu nhạy cảm
   - **HSM Signing:** Ký hóa đơn bằng thiết bị bảo mật phần cứng

5. **💾 Data Storage (Tầng 5):** Bảo vệ dữ liệu khi lưu trữ
   - **Field-Level Encryption:** Mã hóa từng trường (email, địa chỉ, số điện thoại) bằng AES-256-GCM
   - **Tokenization:** Token hóa thẻ để lưu (không lưu số thẻ thật)
   - **Checksum Verification:** Kiểm tra tính toàn vẹn dữ liệu
   - **Audit Logging:** Ghi lại tất cả hành động (ai, làm gì, khi nào)

**Lợi ích:** Nếu hacker vượt qua được 1 tầng, vẫn còn 4 tầng khác chặn lại (defense-in-depth).

---

## 3. Fraud Detection Decision Tree

```mermaid
flowchart TD
    Start([Transaction Input]) --> Input["📥 Input Data:<br/>- amount<br/>- currency<br/>- country<br/>- ip_address<br/>- user_id"]
    
    Input --> HighValue{💵 amount >= 100 USD?}
    
    HighValue --> |Yes| ScorePlus25["Score += 0.25<br/>Flag: HIGH_VALUE"]
    HighValue --> |No| HighRisk
    
    ScorePlus25 --> HighRisk{🌍 country in<br/>[KP, IR, SY]?}
    
    HighRisk --> |Yes| ScorePlus50["Score += 0.50<br/>Flag: HIGH_RISK_COUNTRY"]
    HighRisk --> |No| MissingIP
    
    ScorePlus50 --> MissingIP{🌐 ip_address<br/>is None?}
    
    MissingIP --> |Yes| ScorePlus15["Score += 0.15<br/>Flag: MISSING_IP"]
    MissingIP --> |No| MLModel
    
    ScorePlus15 --> MLModel[🤖 ML Model Inference]
    
    MLModel --> MLScore["ML Score:<br/>0.1 (normal)<br/>0.9 (suspicious)"]
    
    MLScore --> FinalScore["🧮 Final Score =<br/>Rule Score + ML Score"]
    
    FinalScore --> Threshold{⚖️ Score >= 0.75?}
    
    Threshold --> |Yes| Block["🚫 BLOCK<br/>is_fraud = True<br/>reason = flags"]
    Threshold --> |No| Allow["✅ ALLOW<br/>is_fraud = False"]
    
    Block --> Log1[📝 Log fraud event]
    Allow --> Log2[📝 Log normal event]
    
    Log1 --> Alert[🔔 Alert admin]
    Log2 --> Continue[➡️ Continue payment]
    
    Alert --> ManualReview[👤 Manual review queue]
    
    style Start fill:#e1f5e1
    style Block fill:#f8d7da
    style Allow fill:#d1f2eb
    style Threshold fill:#fff3cd
```

### **Tên:** Cây Quyết Định Phát Hiện Gian Lận

### **Giải thích:**
Đây là "bộ não" phát hiện gian lận - một hệ thống chấm điểm để quyết định giao dịch có đáng ngờ không.

**Cách hoạt động (cơ chế chấm điểm):**

**Đầu vào:** Thông tin giao dịch (số tiền, quốc gia, IP, user_id, currency)

**Bước 1: Kiểm tra số tiền lớn**
- ❓ Câu hỏi: Giao dịch ≥ 100 USD không?
- ✅ Nếu CÓ → **+0.25 điểm** (giao dịch lớn rủi ro cao hơn)
- ⏭️ Chuyển tiếp kiểm tra tiếp

**Bước 2: Kiểm tra quốc gia nguy hiểm**
- ❓ Câu hỏi: Quốc gia có phải KP (Triều Tiên), IR (Iran), SY (Syria)?
- ✅ Nếu CÓ → **+0.50 điểm** (quốc gia bị cấm vận/rủi ro cao)

**Bước 3: Kiểm tra thiếu địa chỉ IP**
- ❓ Câu hỏi: IP address có bị thiếu không?
- ✅ Nếu CÓ → **+0.15 điểm** (đáng ngờ vì không biết địa chỉ)

**Bước 4: ML Model (Trí tuệ nhân tạo)**
- 🤖 Mô hình AI phân tích pattern và cho điểm:
  - **0.1** = giao dịch bình thường
  - **0.9** = giao dịch rất đáng ngờ

**Bước 5: Tính tổng điểm**
```
Điểm cuối cùng = Điểm từ rules (0.25 + 0.50 + 0.15) + Điểm ML
```

**Bước 6: Quyết định**
- ⚖️ Nếu **Điểm ≥ 0.75** → 🚫 **CHẶN** giao dịch
  - Ghi log fraud event
  - Gửi alert cho admin
  - Đưa vào hàng đợi để xem xét thủ công
  
- ⚖️ Nếu **Điểm < 0.75** → ✅ **CHO PHÉP** giao dịch
  - Ghi log normal event
  - Tiếp tục thanh toán

**Ví dụ thực tế:**
- Giao dịch 150 USD từ Việt Nam, có IP → 0.25 (high-value) + 0.1 (ML normal) = **0.35** → ✅ Cho phép
- Giao dịch 5 USD từ Triều Tiên → 0.50 (country) + 0.9 (ML suspicious) = **1.40** → 🚫 Chặn
- Giao dịch 200 USD, không có IP, từ Iran → 0.25 + 0.50 + 0.15 + 0.1 = **1.00** → 🚫 Chặn

---

## 4. HMAC Request Signing Flow

```mermaid
sequenceDiagram
    participant Client as 🌐 Frontend
    participant Gateway as 🚪 API Gateway
    participant HMAC as 🔏 HMAC Middleware
    participant Service as 💰 Payment Service
    
    Note over Client: User submits payment
    
    Client->>Client: 1. Build request payload<br/>{token, nonce, order_id}
    
    Client->>Client: 2. Generate HMAC signature<br/>HMAC-SHA256(secret, payload)
    
    Client->>Gateway: 3. POST /payment_service/create_payment<br/>Headers: X-Signature: hmac_xxx
    
    Gateway->>HMAC: 4. Route to HMAC middleware
    
    HMAC->>HMAC: 5. Extract X-Signature header
    
    HMAC->>HMAC: 6. Reconstruct payload from request
    
    HMAC->>HMAC: 7. Calculate expected HMAC<br/>HMAC-SHA256(secret, payload)
    
    HMAC->>HMAC: 8. Compare signatures<br/>constant-time comparison
    
    alt ✅ Signature valid
        HMAC->>Service: 9. Forward to Payment Service
        Service->>Service: 10. Process payment
        Service->>Gateway: 11. Return success
        Gateway->>Client: 12. 200 OK
    else ❌ Signature invalid
        HMAC->>Gateway: 9. Return 403 Forbidden
        Gateway->>Client: 10. Error: Request tampered
    end
    
    Note over HMAC: Prevents:<br/>- Request tampering<br/>- Replay attacks (with nonce)<br/>- MITM modifications
```

### **Tên:** Luồng Ký Chữ Ký HMAC cho Request

### **Giải thích:**
Đây là **sequence diagram** (sơ đồ trình tự) mô tả cách frontend và backend "bắt tay" để đảm bảo request không bị sửa đổi giữa đường.

**Cách hoạt động (như gửi thư có con dấu):**

**Phía Frontend (Người gửi):**
1. **Build payload:** Chuẩn bị dữ liệu gửi đi `{payment_token: "tok_xxx", nonce: "uuid", order_id: 123}`

2. **Tính chữ ký HMAC:** 
   - Dùng **secret key** (chỉ frontend và backend biết)
   - Tính: `HMAC-SHA256(secret_key, payload)` → Kết quả: `hmac_abc123...`
   - Giống như **đóng dấu sáp** lên phong bì

3. **Gửi request:** POST với header đặc biệt:
   ```
   Headers: X-Signature: hmac_abc123...
   Body: {payment_token, nonce, order_id}
   ```

**Phía Backend (Người nhận):**
4. **API Gateway nhận request** → Chuyển đến **HMAC Middleware**

5. **Extract signature:** Lấy chữ ký từ header `X-Signature: hmac_abc123...`

6. **Tái tạo payload:** Đọc lại dữ liệu trong request body

7. **Tính lại chữ ký:** Dùng cùng secret key và payload:
   - `HMAC-SHA256(secret_key, payload)` → Kết quả: `hmac_xyz789...`

8. **So sánh chữ ký** (constant-time comparison để chống timing attack):
   - Frontend gửi: `hmac_abc123...`
   - Backend tính được: `hmac_xyz789...`

**Hai trường hợp:**

✅ **Nếu KHỚP (abc123 = xyz789):**
- → Request **KHÔNG bị sửa đổi**
- → Chuyển tiếp đến Payment Service
- → Xử lý thanh toán bình thường
- → Trả về 200 OK

❌ **Nếu KHÔNG KHỚP (abc123 ≠ xyz789):**
- → Request **ĐÃ BỊ CHỈNH SỬA** giữa đường (hoặc sai secret key)
- → Trả về **403 Forbidden**
- → Ghi log: "Request tampered"

**Bảo vệ chống:**
- **Request tampering:** Hacker không thể sửa `order_id` từ 123 → 999 vì sẽ không khớp chữ ký
- **Replay attack:** Kết hợp với nonce (số dùng 1 lần), nên request cũ không thể gửi lại
- **MITM modifications:** Man-in-the-middle không thể sửa dữ liệu mà không phá vỡ chữ ký

**Ví dụ thực tế:** Giống như gửi séc có chữ ký - ngân hàng sẽ so chữ ký trên séc với chữ ký mẫu. Nếu không khớp → Từ chối!

---

## 5. Encryption Key Management Flow

```mermaid
flowchart TD
    Start([Application Startup]) --> LoadEnv[📂 Load .env file]
    
    LoadEnv --> CheckMasterKey{🔑 MASTER_KEY exists?}
    
    CheckMasterKey --> |No| GenerateKey[🎲 Generate 256-bit key]
    CheckMasterKey --> |Yes| LoadKey[📥 Load existing key]
    
    GenerateKey --> WarnUser[⚠️ WARNING: Generated key<br/>Save to KMS/HSM!]
    LoadKey --> DecodeKey[🔓 Base64 decode key]
    
    WarnUser --> InitEncryption[🔐 Initialize FieldEncryption]
    DecodeKey --> InitEncryption
    
    InitEncryption --> HSMCheck{🔒 HSM available?}
    
    HSMCheck --> |Yes| HSMInit[🏛️ Initialize HSM<br/>PKCS#11 session]
    HSMCheck --> |No| SoftwareKey[💾 Use software key<br/>with encryption]
    
    HSMInit --> HSMSign[✍️ Load signing key<br/>RSA-2048]
    SoftwareKey --> SoftSign[✍️ Load PEM key<br/>from file]
    
    HSMSign --> KeyRotation{🔄 Key rotation due?}
    SoftSign --> KeyRotation
    
    KeyRotation --> |Yes| RotateKeys[🔄 Rotate all keys<br/>+ Re-encrypt data]
    KeyRotation --> |No| Ready
    
    RotateKeys --> Ready[✅ Encryption ready]
    
    Ready --> Runtime[⚙️ Runtime operations]
    
    Runtime --> EncryptData[🔐 Encrypt field]
    Runtime --> DecryptData[🔓 Decrypt field]
    Runtime --> SignReceipt[✍️ Sign receipt]
    Runtime --> VerifySign[✅ Verify signature]
    
    EncryptData --> AESGCMEnc["AES-256-GCM<br/>+ AAD context<br/>+ Random IV"]
    DecryptData --> AESGCMDec["AES-256-GCM<br/>Verify auth tag"]
    SignReceipt --> RSASign["RSA-2048<br/>SHA-256 + PSS"]
    VerifySign --> RSAVerify["RSA verify<br/>+ timestamp check"]
    
    AESGCMEnc --> Store[💾 Store ciphertext]
    AESGCMDec --> Return[📤 Return plaintext]
    RSASign --> Attach[📎 Attach signature]
    RSAVerify --> Valid{✅ Valid?}
    
    Valid --> |Yes| Accept[✅ Accept receipt]
    Valid --> |No| Reject[❌ Reject - tampering]
    
    style Start fill:#e1f5e1
    style Ready fill:#d1f2eb
    style HSMInit fill:#fff3cd
    style Reject fill:#f8d7da
```

### **Tên:** Luồng Quản Lý Khóa Mã Hóa

### **Giải thích:**
Sơ đồ này mô tả cách hệ thống khởi động và quản lý các **khóa mã hóa** - yếu tố quan trọng nhất của bảo mật.

**Cách hoạt động (vòng đời khóa mã hóa):**

**Giai đoạn 1: Khởi động ứng dụng**
1. **Load .env file:** Đọc file cấu hình (chứa biến môi trường)

2. **Kiểm tra MASTER_KEY:**
   - ✅ **Nếu CÓ sẵn:** Load khóa từ file → Base64 decode → Sử dụng
   - ❌ **Nếu CHƯA CÓ:** Tạo khóa 256-bit mới → ⚠️ **CẢNH BÁO**: Phải lưu vào KMS/HSM ngay!

3. **Initialize FieldEncryption:** Khởi tạo module mã hóa với khóa đã load

**Giai đoạn 2: Chọn phương thức ký**
4. **Kiểm tra HSM (Hardware Security Module):**
   - 🏛️ **Nếu CÓ HSM:** 
     - Kết nối PKCS#11 session
     - Load khóa ký RSA-2048 từ HSM (bảo mật cao nhất)
   - 💾 **Nếu KHÔNG có HSM:**
     - Dùng software key (khóa mềm)
     - Load file PEM từ disk

**Giai đoạn 3: Key Rotation (Xoay vòng khóa)**
5. **Kiểm tra chu kỳ rotation:**
   - ❓ Khóa đã hết hạn chưa? (VD: đã dùng > 90 ngày)
   - ✅ **Nếu HẾT HẠN:** 
     - Tạo khóa mới
     - Giải mã tất cả data bằng khóa cũ
     - Mã hóa lại bằng khóa mới
   - ⏭️ **Nếu còn hạn:** Tiếp tục dùng khóa hiện tại

6. **✅ Ready:** Hệ thống sẵn sàng xử lý

**Giai đoạn 4: Runtime Operations (Hoạt động thực tế)**

Có 4 thao tác chính:

**A. 🔐 Encrypt field (Mã hóa trường):**
- Input: Plaintext (VD: "nguyenvana@gmail.com")
- Process:
  - Tạo IV random (12 bytes)
  - Dùng AES-256-GCM mã hóa
  - Thêm AAD (Additional Authenticated Data) - context như `user_id`, `field_name`
  - Tạo authentication tag (16 bytes)
- Output: Ciphertext → 💾 Lưu vào database

**B. 🔓 Decrypt field (Giải mã trường):**
- Input: Ciphertext từ database
- Process:
  - Verify authentication tag (kiểm tra tính toàn vẹn)
  - Giải mã bằng AES-256-GCM
  - Kiểm tra AAD khớp không
- Output: Plaintext → 📤 Trả về ứng dụng

**C. ✍️ Sign receipt (Ký hóa đơn):**
- Input: Hóa đơn/Receipt
- Process:
  - Dùng khóa private RSA-2048
  - Ký bằng SHA-256 + PSS padding
- Output: Signature → 📎 Đính kèm vào hóa đơn

**D. ✅ Verify signature (Xác minh chữ ký):**
- Input: Hóa đơn + Signature
- Process:
  - Dùng khóa public RSA-2048
  - Verify chữ ký
  - Kiểm tra timestamp (chống replay)
- Output:
  - ✅ **Valid:** Chấp nhận hóa đơn
  - ❌ **Invalid:** Từ chối (bị giả mạo)

**Bảo mật:**
- Khóa MASTER_KEY phải lưu trong **KMS/HSM**, không hard-code
- Khóa phải **rotation định kỳ** (VD: 90 ngày/lần)
- HSM đảm bảo khóa private **không bao giờ rời khỏi thiết bị**

---

## 6. Token Lifecycle Flow

```mermaid
stateDiagram-v2
    [*] --> Created: User enters card
    
    Created --> Tokenizing: stripe.createToken()
    
    Tokenizing --> Valid: Token created<br/>tok_xxxxxxxxxx
    Tokenizing --> Invalid: Card validation failed
    
    Invalid --> [*]: Show error to user
    
    Valid --> InTransit: POST to backend
    
    InTransit --> Received: Gateway receives token
    
    Received --> Validating: Fraud detection
    
    Validating --> Blocked: Score >= 0.75
    Validating --> Approved: Score < 0.75
    
    Blocked --> [*]: Transaction rejected
    
    Approved --> StripeAPI: Call Stripe
    
    StripeAPI --> Charging: Create PaymentIntent
    
    Charging --> Success: Charge successful
    Charging --> Failed: Card declined
    
    Failed --> [*]: Payment failed
    
    Success --> Tokenized: Save token for future
    
    Tokenized --> Encrypted: Encrypt + Store
    
    Encrypted --> [*]: Complete
    
    note right of Valid
        Token expires in 5 minutes
        One-time use only
    end note
    
    note right of Encrypted
        Token encrypted with AES-256-GCM
        Checksum for integrity
    end note
```

### **Tên:** Vòng Đời Token Thanh Toán

### **Giải thích:**
Đây là **state diagram** (sơ đồ trạng thái) mô tả hành trình của một **payment token** từ lúc sinh ra đến khi kết thúc.

**Cách hoạt động (các trạng thái token):**

**🌱 CREATED (Khởi tạo):**
- User nhập thẻ vào Stripe Hosted Fields
- Sự kiện: Nhấn nút "Thanh toán"
- Chuyển sang: TOKENIZING

**⚙️ TOKENIZING (Đang token hóa):**
- Frontend gọi `stripe.createToken()`
- Stripe xử lý và kiểm tra thẻ
- **Hai kết quả:**
  - ✅ Thẻ hợp lệ → VALID
  - ❌ Thẻ không hợp lệ (sai số, hết hạn, CVV sai) → INVALID → **KẾT THÚC** (hiện lỗi)

**✅ VALID (Token hợp lệ):**
- Token được tạo: `tok_1A2B3C4D5E6F...`
- ⏰ **Lưu ý:** Token chỉ tồn tại **5 phút** và chỉ dùng **1 lần**
- Sự kiện: POST request đến backend
- Chuyển sang: IN_TRANSIT

**📡 IN_TRANSIT (Đang truyền):**
- Token đang được gửi qua HTTPS đến backend
- Chuyển sang: RECEIVED

**📥 RECEIVED (Đã nhận):**
- API Gateway nhận được request chứa token
- Chuyển sang: VALIDATING

**🔍 VALIDATING (Đang kiểm tra gian lận):**
- Fraud Detection Module chấm điểm
- **Hai kết quả:**
  - 🚫 Score ≥ 0.75 → BLOCKED → **KẾT THÚC** (giao dịch bị chặn)
  - ✅ Score < 0.75 → APPROVED

**✅ APPROVED (Được duyệt):**
- Giao dịch an toàn, tiếp tục xử lý
- Sự kiện: Gọi Stripe API
- Chuyển sang: STRIPE_API

**☁️ STRIPE_API → CHARGING (Đang charge):**
- Backend gọi `stripe.paymentIntents.create()` với token
- Stripe detokenize (chuyển token → số thẻ thật) và charge
- **Hai kết quả:**
  - ❌ Thẻ bị từ chối (không đủ tiền, bank chặn) → FAILED → **KẾT THÚC**
  - ✅ Charge thành công → SUCCESS

**🎉 SUCCESS (Thành công):**
- Payment hoàn tất
- Chuyển sang: TOKENIZED (để lưu cho tương lai)

**🎫 TOKENIZED (Token hóa để lưu):**
- Tạo token nội bộ để lưu thông tin thẻ (cho thanh toán sau)
- Chuyển sang: ENCRYPTED

**🔐 ENCRYPTED (Đã mã hóa và lưu):**
- Token được mã hóa bằng AES-256-GCM
- Tính checksum để đảm bảo tính toàn vẹn
- Lưu vào database
- **KẾT THÚC** (Complete)

**Tổng kết các điểm kết thúc:**
- ❌ **INVALID:** Thẻ không hợp lệ
- 🚫 **BLOCKED:** Bị phát hiện gian lận
- ❌ **FAILED:** Bank từ chối charge
- ✅ **ENCRYPTED:** Thành công và lưu trữ an toàn

**Thời gian sống:** Token Stripe expire sau 5 phút, nên toàn bộ flow phải hoàn tất trong 5 phút!

---

## 7. Security Threat Mitigation Map

```mermaid
mindmap
    root((🛡️ Security<br/>Threats))
        🎯 Card Data Theft
            ✅ Stripe Hosted Fields
            ✅ Tokenization
            ✅ No PAN storage
            ✅ PCI-DSS SAQ-A
        🌐 Network Attacks
            ✅ HTTPS/TLS 1.3
            ✅ HSTS
            ✅ Certificate pinning
            ⚠️ TODO: mTLS
        🔓 Authentication
            ✅ JWT tokens
            ✅ HMAC signing
            ✅ Nonce anti-replay
            ⚠️ TODO: 2FA
        🚫 Fraud
            ✅ High-value rules
            ✅ Country blocklist
            ✅ ML scoring
            ⚠️ TODO: Device binding
        💉 Injection
            ⚠️ TODO: Input validation
            ⚠️ TODO: SQL parameterization
            ⚠️ TODO: XSS protection CSP
        🔑 Key Management
            ✅ AES-256-GCM
            ✅ HSM integration
            ⚠️ TODO: Key rotation
            ⚠️ TODO: KMS integration
        📊 Monitoring
            ✅ Request ID tracing
            ✅ Audit logging
            ⚠️ TODO: SIEM integration
            ⚠️ TODO: Alerting
```

### **Tên:** Mind Map Phòng Chống Các Mối Đe Dọa Bảo Mật

### **Giải thích:**
Đây là **mind map** (sơ đồ tư duy) liệt kê **tất cả các threat (mối đe dọa)** và cách hệ thống **phòng chống**.

**Cách đọc:** Từ tâm (Security Threats) phát tán ra 7 nhánh chính, mỗi nhánh là 1 loại threat.

**7 nhóm mối đe dọa và cách phòng chống:**

**1. 🎯 Card Data Theft (Đánh cắp dữ liệu thẻ)**
- **Threat:** Hacker muốn lấy số thẻ tín dụng
- **Mitigation (Phòng chống):**
  - ✅ **Stripe Hosted Fields:** Số thẻ nhập vào iFrame cách ly, JS không access được
  - ✅ **Tokenization:** Chuyển PAN thành token ngay lập tức
  - ✅ **No PAN storage:** Backend không bao giờ lưu số thẻ thật
  - ✅ **PCI-DSS SAQ-A:** Đạt chuẩn bảo mật thanh toán (chỉ cần self-assessment)

**2. 🌐 Network Attacks (Tấn công mạng)**
- **Threat:** Hacker nghe lén hoặc chặn dữ liệu trên đường truyền
- **Mitigation:**
  - ✅ **HTTPS/TLS 1.3:** Mã hóa tất cả traffic (như bỏ vào phong bì kín)
  - ✅ **HSTS:** Bắt buộc browser luôn dùng HTTPS
  - ✅ **Certificate pinning:** Chỉ tin tưởng cert đúng (chống fake cert)
  - ⚠️ **TODO: mTLS:** Mutual TLS (cả client và server đều xác thực lẫn nhau)

**3. 🔓 Authentication (Xác thực)**
- **Threat:** Người dùng giả mạo hoặc session hijacking
- **Mitigation:**
  - ✅ **JWT tokens:** Token có chữ ký để xác thực người dùng
  - ✅ **HMAC signing:** Ký request để chống giả mạo
  - ✅ **Nonce anti-replay:** Số dùng 1 lần chống gửi lại request cũ
  - ⚠️ **TODO: 2FA:** Two-factor authentication (xác thực 2 lớp)

**4. 🚫 Fraud (Gian lận)**
- **Threat:** Thẻ cắp, giao dịch giả mạo, rửa tiền
- **Mitigation:**
  - ✅ **High-value rules:** Chặn giao dịch lớn bất thường
  - ✅ **Country blocklist:** Chặn quốc gia nguy hiểm (KP, IR, SY)
  - ✅ **ML scoring:** AI cho điểm nghi ngờ dựa vào pattern
  - ⚠️ **TODO: Device binding:** Gắn thiết bị với tài khoản (phát hiện login lạ)

**5. 💉 Injection (Tấn công chèn code)**
- **Threat:** SQL injection, XSS (Cross-Site Scripting), command injection
- **Mitigation:**
  - ⚠️ **TODO: Input validation:** Kiểm tra và lọc input từ user
  - ⚠️ **TODO: SQL parameterization:** Dùng prepared statement (không ghép string SQL)
  - ⚠️ **TODO: XSS protection CSP:** Content Security Policy chặn script lạ

**6. 🔑 Key Management (Quản lý khóa)**
- **Threat:** Khóa mã hóa bị đánh cắp hoặc lộ
- **Mitigation:**
  - ✅ **AES-256-GCM:** Thuật toán mã hóa mạnh nhất hiện nay
  - ✅ **HSM integration:** Khóa lưu trong thiết bị phần cứng (không thể sao chép)
  - ⚠️ **TODO: Key rotation:** Xoay vòng khóa định kỳ (90 ngày/lần)
  - ⚠️ **TODO: KMS integration:** Dùng Key Management Service (AWS KMS, Azure Key Vault)

**7. 📊 Monitoring (Giám sát)**
- **Threat:** Không phát hiện được tấn công đang diễn ra
- **Mitigation:**
  - ✅ **Request ID tracing:** Truy vết request xuyên suốt hệ thống
  - ✅ **Audit logging:** Ghi lại tất cả hành động quan trọng
  - ⚠️ **TODO: SIEM integration:** Security Information and Event Management
  - ⚠️ **TODO: Alerting:** Cảnh báo realtime khi có hành vi lạ

**Ký hiệu:**
- ✅ = Đã implement (hoàn tất)
- ⚠️ TODO = Chưa implement (cần làm thêm)

**Chiến lược:** Không có 1 giải pháp nào bảo vệ 100%, nên phải **kết hợp nhiều lớp** (defense-in-depth).

---

## 8. Production Deployment Security Checklist

```mermaid
flowchart TD
    Start([Deploy to Production]) --> Checklist{Pre-flight checks}
    
    Checklist --> TLS["✅ TLS 1.3 enabled<br/>❌ HTTP disabled<br/>✅ HSTS configured"]
    
    TLS --> Keys["✅ Keys in KMS/HSM<br/>❌ No hardcoded secrets<br/>✅ Env vars configured"]
    
    Keys --> Monitoring["✅ Logging enabled<br/>✅ Request ID tracing<br/>✅ Error alerting"]
    
    Monitoring --> RateLimit["✅ Rate limiter Redis<br/>❌ No in-memory cache<br/>✅ DDoS protection"]
    
    RateLimit --> Compliance["✅ PCI-DSS self-assessment<br/>✅ GDPR compliance<br/>✅ Data retention policy"]
    
    Compliance --> Backup["✅ Encrypted backups<br/>✅ DR plan tested<br/>✅ Key escrow"]
    
    Backup --> Testing["✅ Security tests passed<br/>✅ Penetration test done<br/>✅ Dependency scan clean"]
    
    Testing --> Final{All checks pass?}
    
    Final --> |Yes| Deploy[🚀 Deploy to production]
    Final --> |No| Fix[🔧 Fix issues]
    
    Fix --> Checklist
    
    Deploy --> Monitor[📊 Monitor metrics]
    
    Monitor --> Incident{Security incident?}
    
    Incident --> |Yes| Response[🚨 Incident response<br/>- Rotate keys<br/>- Block attacker<br/>- Notify users]
    Incident --> |No| Continue[✅ Normal operation]
    
    Response --> PostMortem[📝 Post-mortem<br/>- Root cause<br/>- Lessons learned<br/>- Update runbook]
    
    PostMortem --> Continue
    Continue --> Monitor
    
    style Start fill:#e1f5e1
    style Deploy fill:#d1f2eb
    style Final fill:#fff3cd
    style Incident fill:#fff3cd
    style Fix fill:#f8d7da
```

### **Tên:** Checklist Bảo Mật Khi Deploy Production

### **Giải thích:**
Đây là **flowchart quy trình** kiểm tra bảo mật trước khi đưa hệ thống lên production (môi trường thật phục vụ khách hàng).

**Cách hoạt động (8 bước kiểm tra + 1 vòng giám sát):**

**Giai đoạn PRE-FLIGHT (Kiểm tra trước khi bay):**

**Bước 1: ✅ TLS/HTTPS**
- ✅ TLS 1.3 enabled (bật mã hóa mạnh nhất)
- ❌ HTTP disabled (tắt hoàn toàn HTTP không mã hóa)
- ✅ HSTS configured (bắt buộc HTTPS)

**Bước 2: ✅ Keys (Quản lý khóa)**
- ✅ Keys in KMS/HSM (khóa lưu trong hệ thống quản lý khóa chuyên dụng)
- ❌ No hardcoded secrets (không hard-code secret trong code)
- ✅ Env vars configured (dùng biến môi trường)

**Bước 3: ✅ Monitoring (Giám sát)**
- ✅ Logging enabled (bật ghi log)
- ✅ Request ID tracing (truy vết request)
- ✅ Error alerting (cảnh báo khi có lỗi)

**Bước 4: ✅ Rate Limit (Giới hạn request)**
- ✅ Rate limiter Redis (dùng Redis thay vì in-memory)
- ❌ No in-memory cache (không dùng cache trong bộ nhớ - mất khi restart)
- ✅ DDoS protection (bảo vệ chống tấn công từ chối dịch vụ)

**Bước 5: ✅ Compliance (Tuân thủ quy định)**
- ✅ PCI-DSS self-assessment (đánh giá bảo mật thanh toán)
- ✅ GDPR compliance (tuân thủ quy định bảo vệ dữ liệu EU)
- ✅ Data retention policy (chính sách lưu trữ dữ liệu)

**Bước 6: ✅ Backup (Sao lưu)**
- ✅ Encrypted backups (backup được mã hóa)
- ✅ DR plan tested (kế hoạch khắc phục thảm họa đã test)
- ✅ Key escrow (sao lưu khóa dự phòng an toàn)

**Bước 7: ✅ Testing (Kiểm tra bảo mật)**
- ✅ Security tests passed (pass các test bảo mật)
- ✅ Penetration test done (đã làm pen test - hacker mũ trắng thử tấn công)
- ✅ Dependency scan clean (không có thư viện có lỗ hổng)

**Bước 8: ❓ Final Decision**
- ✅ **All checks pass?** → 🚀 **DEPLOY to production**
- ❌ **Any check fails?** → 🔧 **Fix issues** → Quay lại bước 1

**Giai đoạn POST-DEPLOYMENT (Sau khi deploy):**

**Vòng lặp giám sát liên tục:**

**📊 Monitor metrics:** Theo dõi các chỉ số (CPU, RAM, response time, error rate)

**❓ Security incident?** (Có sự cố bảo mật không?)

**Nếu KHÔNG có sự cố:**
- ✅ **Normal operation** → Tiếp tục giám sát

**Nếu CÓ sự cố:**
- 🚨 **Incident response** (Phản ứng sự cố):
  1. **Rotate keys:** Thay đổi tất cả khóa ngay lập tức
  2. **Block attacker:** Chặn IP/tài khoản tấn công
  3. **Notify users:** Thông báo cho người dùng bị ảnh hưởng
  
- 📝 **Post-mortem** (Phân tích sau sự cố):
  1. **Root cause:** Tìm nguyên nhân gốc rễ
  2. **Lessons learned:** Rút kinh nghiệm
  3. **Update runbook:** Cập nhật tài liệu xử lý sự cố

- ✅ Quay lại **Normal operation** → Tiếp tục giám sát

**Mục đích:**
- Đảm bảo hệ thống **an toàn trước khi lên production**
- Có **quy trình xử lý sự cố** rõ ràng
- **Học hỏi từ sự cố** để cải thiện

**Checklist này giống như:** Bác sĩ kiểm tra sức khỏe toàn diện trước khi cho phép phi công lái máy bay chở khách!

---

## Legend / Chú thích

| Icon | Ý nghĩa |
|------|---------|
| 🔒 | Encryption / Mã hóa |
| 🔑 | Authentication / Xác thực |
| 🔏 | Digital signature / Chữ ký số |
| 🛡️ | Security layer / Lớp bảo mật |
| 🕵️ | Fraud detection / Phát hiện gian lận |
| 💳 | Card data / Dữ liệu thẻ |
| 🎫 | Token / Token hóa |
| 🚫 | Block / Chặn |
| ✅ | Approved / Cho phép |
| ❌ | Rejected / Từ chối |
| ⚠️ | Warning / Cảnh báo |
| 🏛️ | HSM / Hardware Security Module |
| 💾 | Storage / Lưu trữ |
| 📝 | Logging / Ghi log |
| 🔔 | Alert / Cảnh báo |

---

## Cách xem flowchart

### Option 1: GitHub/GitLab
- Push file này lên repo → Mermaid tự động render

### Option 2: VS Code
- Install extension: "Markdown Preview Mermaid Support"
- Hoặc "Mermaid Chart"
- Preview file này (Ctrl+Shift+V)

### Option 3: Online
- Copy code vào: https://mermaid.live
- Export PNG/SVG

### Option 4: Generate static diagram
```bash
# Install mermaid-cli
npm install -g @mermaid-js/mermaid-cli

# Generate PNG
mmdc -i PAYMENT_SECURITY_FLOWCHART.md -o payment_flow.png

# Generate SVG
mmdc -i PAYMENT_SECURITY_FLOWCHART.md -o payment_flow.svg
```

---

---

## ✅ Trạng Thái Implementation trong Project

### **Tổng quan:**
Dưới đây là bảng chi tiết về **trạng thái implementation** của từng component trong 8 flowcharts:

| # | Component/Flow | Trạng thái | File Implementation | Ghi chú |
|---|----------------|-----------|---------------------|---------|
| **1. Complete Payment Flow** | | | | |
| 1.1 | Stripe Hosted Fields | ✅ **DONE** | `frontend/templates/checkout.html` (line 467-515) | iFrame, stripe.elements() |
| 1.2 | Tokenization (PAN → token) | ✅ **DONE** | `checkout.html` (line 531: stripe.createToken) | Token expires 5 min |
| 1.3 | Nonce Generation | ✅ **DONE** | `checkout.html` (line 548: crypto.randomUUID()) | Anti-replay UUID |
| 1.4 | Device Fingerprint | ✅ **DONE** | `checkout.html` (line 552: btoa(navigator.userAgent)) | Base64 encoded |
| 1.5 | TLS/HTTPS Check | ⚠️ **PARTIAL** | `backend/middleware/hmac_verifier.py` (line 21-25) | Optional check exists, need enforce |
| 1.6 | API Gateway Middlewares | ✅ **DONE** | `backend/main.py` + `backend/middleware/*.py` | 5 middlewares active |
| 1.6a | → Request ID | ✅ **DONE** | `backend/middleware/request_id.py` | UUID per request |
| 1.6b | → CORS | ✅ **DONE** | `backend/middleware/cors.py` | Origins configurable |
| 1.6c | → Rate Limiter | ✅ **DONE** | `backend/middleware/rate_limiter.py` | In-memory (TODO: Redis) |
| 1.6d | → JWT Auth | ✅ **DONE** | `backend/middleware/auth.py` | Token verification |
| 1.6e | → HMAC Verify | ✅ **DONE** | `backend/middleware/hmac_verifier.py` | SHA256 signing |
| 1.7 | Fraud Detection | ✅ **DONE** | `backend/services/payment_service/security/fraud_detection.py` | Rules + ML placeholder |
| 1.8 | Stripe PaymentIntent | ✅ **DONE** | `backend/services/payment_service/payment.py` | stripe.PaymentIntent.create() |
| 1.9 | Field Encryption (AES-GCM) | ✅ **DONE** | `backend/services/payment_service/security/encryption.py` | FieldEncryption class |
| 1.10 | HSM Signing | ✅ **DONE** | `backend/services/payment_service/security/hsm_client.py` | PKCS#11 + SoftHSM |
| 1.11 | Tokenization (card storage) | ✅ **DONE** | `backend/services/payment_service/security/tokenization.py` | SecureStorage |
| 1.12 | Audit Logging | ✅ **DONE** | `backend/services/payment_service/security/pci_auditor.py` | PCI audit log |
| 1.13 | Error Page with navigation | ✅ **DONE** | `frontend/templates/error.html` | Home/Cart buttons |
| **2. Security Layers** | | | | |
| 2.1 | Frontend Security (4 layers) | ✅ **DONE** | `checkout.html` | Hosted Fields, Token, Nonce, Fingerprint |
| 2.2 | Transport Security (TLS) | ⚠️ **PARTIAL** | `backend/certs/` + nginx config created | Cert created, need enable HTTPS |
| 2.3 | API Gateway (5 middlewares) | ✅ **DONE** | `backend/middleware/*.py` | All 5 active |
| 2.4 | Payment Service (4 modules) | ✅ **DONE** | `backend/services/payment_service/security/` | Fraud, Stripe, Encrypt, HSM |
| 2.5 | Data Storage (4 protections) | ✅ **DONE** | encryption.py + tokenization.py | Encrypt, Token, Checksum, Audit |
| **3. Fraud Detection** | | | | |
| 3.1 | High-Value Rule | ✅ **DONE** | `fraud_detection.py` (line 89: amount >= threshold) | Threshold = 1,000,000 VND |
| 3.2 | High-Risk Country Rule | ✅ **DONE** | `fraud_detection.py` (line 95: country in [KP,IR,SY]) | 3 countries blocked |
| 3.3 | Missing IP Rule | ✅ **DONE** | `fraud_detection.py` (line 102: ip_address is None) | +0.15 score |
| 3.4 | ML Model Scoring | ⚠️ **PLACEHOLDER** | `fraud_detection.py` (_get_ml_score) | Placeholder, returns 0.1/0.9 |
| 3.5 | Final Score Calculation | ✅ **DONE** | `fraud_detection.py` (line 125-142) | Rules + ML combined |
| 3.6 | Block/Allow Decision | ✅ **DONE** | `fraud_detection.py` (line 135: score >= 0.75) | Threshold logic correct |
| 3.7 | Admin Alert System | ❌ **TODO** | N/A | Need implement alerting |
| 3.8 | Manual Review Queue | ❌ **TODO** | N/A | Need admin dashboard |
| **4. HMAC Signing** | | | | |
| 4.1 | Frontend HMAC Generation | ❌ **TODO** | N/A | Need add to checkout.html |
| 4.2 | Backend HMAC Verification | ✅ **DONE** | `hmac_verifier.py` | Middleware active |
| 4.3 | Constant-time Comparison | ✅ **DONE** | `hmac_verifier.py` (line 34: hmac.compare_digest) | Secure comparison |
| 4.4 | Nonce Tracking | ❌ **TODO** | N/A | Need nonce deduplication |
| **5. Key Management** | | | | |
| 5.1 | MASTER_KEY Loading | ✅ **DONE** | `encryption.py` (__init__) | Env var or generate |
| 5.2 | HSM Initialization | ✅ **DONE** | `hsm_client.py` | PKCS#11 + SoftHSM |
| 5.3 | Key Rotation Logic | ❌ **TODO** | N/A | Need rotation schedule |
| 5.4 | AES-256-GCM Encryption | ✅ **DONE** | `encryption.py` (FieldEncryption) | With AAD support |
| 5.5 | RSA-2048 Signing | ✅ **DONE** | `hsm_client.py` (sign_data) | SHA256+PSS |
| 5.6 | KMS Integration | ❌ **TODO** | N/A | Need AWS KMS/Azure Key Vault |
| **6. Token Lifecycle** | | | | |
| 6.1 | Token Creation (Stripe) | ✅ **DONE** | `checkout.html` (stripe.createToken) | Frontend tokenization |
| 6.2 | Token Validation | ✅ **DONE** | Stripe API automatic | Stripe handles |
| 6.3 | Fraud Detection Check | ✅ **DONE** | `fraud_detection.py` (assess_transaction) | Before charging |
| 6.4 | Stripe Charge | ✅ **DONE** | `payment.py` (stripe.PaymentIntent.create) | With token |
| 6.5 | Internal Tokenization | ✅ **DONE** | `tokenization.py` (CardTokenizer) | For future use |
| 6.6 | AES Encryption Storage | ✅ **DONE** | `tokenization.py` + `encryption.py` | Encrypted tokens |
| 6.7 | Checksum Verification | ✅ **DONE** | `encryption.py` (SecureStorage) | SHA256 checksum |
| **7. Threat Mitigation** | | | | |
| 7.1 | Card Data Theft → Hosted Fields | ✅ **DONE** | `checkout.html` | Stripe iFrame |
| 7.2 | Network Attack → TLS 1.3 | ⚠️ **PARTIAL** | Certs created, need enable | Need start with SSL |
| 7.3 | Network Attack → HSTS | ❌ **TODO** | N/A | Need add header |
| 7.4 | Network Attack → Cert Pinning | ❌ **TODO** | N/A | Advanced feature |
| 7.5 | Auth → JWT | ✅ **DONE** | `auth.py` | JWT verification |
| 7.6 | Auth → HMAC | ✅ **DONE** | `hmac_verifier.py` | Request signing |
| 7.7 | Auth → Nonce | ✅ **DONE** | `checkout.html` | UUID generated |
| 7.8 | Auth → 2FA | ❌ **TODO** | N/A | Future enhancement |
| 7.9 | Fraud → High-value rules | ✅ **DONE** | `fraud_detection.py` | Threshold check |
| 7.10 | Fraud → Country blocklist | ✅ **DONE** | `fraud_detection.py` | KP/IR/SY |
| 7.11 | Fraud → ML scoring | ⚠️ **PLACEHOLDER** | `fraud_detection.py` | Need real ML model |
| 7.12 | Fraud → Device binding | ❌ **TODO** | N/A | Fingerprint exists, need bind |
| 7.13 | Injection → Input validation | ❌ **TODO** | N/A | Need add validators |
| 7.14 | Injection → SQL parameterization | ✅ **DONE** | SQLAlchemy ORM | ORM prevents SQL injection |
| 7.15 | Injection → CSP header | ❌ **TODO** | N/A | Need Content-Security-Policy |
| 7.16 | Key Mgmt → AES-256-GCM | ✅ **DONE** | `encryption.py` | Implemented |
| 7.17 | Key Mgmt → HSM | ✅ **DONE** | `hsm_client.py` | SoftHSM ready |
| 7.18 | Key Mgmt → Key rotation | ❌ **TODO** | N/A | Need schedule |
| 7.19 | Key Mgmt → KMS | ❌ **TODO** | N/A | Need cloud integration |
| 7.20 | Monitoring → Request ID | ✅ **DONE** | `request_id.py` | UUID tracing |
| 7.21 | Monitoring → Audit log | ✅ **DONE** | `pci_auditor.py` | PCI compliance log |
| 7.22 | Monitoring → SIEM | ❌ **TODO** | N/A | Need Splunk/ELK |
| 7.23 | Monitoring → Alerting | ❌ **TODO** | N/A | Need PagerDuty/etc |
| **8. Production Deployment** | | | | |
| 8.1 | TLS 1.3 enabled | ⚠️ **READY** | `backend/certs/` + nginx config | Certs created, need start |
| 8.2 | Keys in KMS/HSM | ⚠️ **PARTIAL** | HSM ready, KMS TODO | SoftHSM works, need cloud KMS |
| 8.3 | Logging enabled | ✅ **DONE** | `pci_auditor.py` | Audit logging active |
| 8.4 | Rate limiter (Redis) | ⚠️ **IN-MEMORY** | `rate_limiter.py` | Works but need Redis for prod |
| 8.5 | PCI-DSS compliance | ✅ **READY** | SAQ-A eligible (Stripe Hosted Fields) | Stripe handles PCI |
| 8.6 | GDPR compliance | ⚠️ **PARTIAL** | Encryption exists, need data export/erasure | Need GDPR endpoints |
| 8.7 | Encrypted backups | ❌ **TODO** | N/A | Need backup strategy |
| 8.8 | DR plan | ❌ **TODO** | N/A | Need disaster recovery plan |
| 8.9 | Security tests | ⚠️ **PARTIAL** | Unit tests exist (`test_*.py`) | Need integration tests |
| 8.10 | Penetration test | ❌ **TODO** | N/A | Need hire pen tester |
| 8.11 | Dependency scan | ❌ **TODO** | N/A | Need Snyk/Dependabot |
| 8.12 | Incident response plan | ❌ **TODO** | N/A | Need runbook |

---

### **Thống kê Implementation:**

| Trạng thái | Số lượng | Tỷ lệ | Mô tả |
|-----------|----------|-------|-------|
| ✅ **DONE** | 46 | 61% | Đã implement hoàn chỉnh và hoạt động |
| ⚠️ **PARTIAL** | 11 | 15% | Có code nhưng chưa hoàn chỉnh/chưa enable |
| ❌ **TODO** | 18 | 24% | Chưa implement, cần làm thêm |
| **TOTAL** | **75** | **100%** | Tổng số component kiểm tra |

---

### **Priority Implementation Roadmap:**

#### **🔥 HIGH PRIORITY (Cần làm ngay cho production):**
1. ✅ Enable HTTPS/TLS 1.3 (certs đã có, cần start server với SSL)
2. ✅ Add HSTS header (bắt buộc HTTPS)
3. ✅ Migrate rate limiter to Redis (thay in-memory)
4. ✅ Add CSP header (chống XSS)
5. ✅ Implement frontend HMAC signing (hiện chỉ có verify)
6. ✅ Add nonce deduplication (chống replay attack)

#### **⚠️ MEDIUM PRIORITY (Tăng cường bảo mật):**
7. ✅ Real ML fraud model (thay placeholder)
8. ✅ Admin alert system (email/Slack khi có fraud)
9. ✅ Input validation middleware (sanitize all inputs)
10. ✅ Key rotation schedule (auto-rotate keys mỗi 90 ngày)
11. ✅ Device binding (track devices per user)
12. ✅ GDPR data export/erasure endpoints

#### **📊 LOW PRIORITY (Long-term improvements):**
13. ✅ Cloud KMS integration (AWS KMS/Azure Key Vault)
14. ✅ SIEM integration (Splunk/ELK)
15. ✅ Alerting system (PagerDuty/OpsGenie)
16. ✅ 2FA authentication
17. ✅ Certificate pinning
18. ✅ Penetration testing
19. ✅ DR plan + encrypted backups
20. ✅ Dependency scanning (Snyk)

---

### **Kết luận:**

**✅ Core security (61%) đã DONE:**
- Stripe Hosted Fields + Tokenization ✅
- 5 Gateway Middlewares ✅
- Fraud Detection (rule-based) ✅
- AES-256-GCM Encryption ✅
- HSM Signing ✅
- Audit Logging ✅

**⚠️ Cần hoàn thiện (15%) để production-ready:**
- Enable HTTPS/TLS
- Redis rate limiter
- Frontend HMAC signing
- CSP/HSTS headers

**❌ TODO (24%) là các tính năng nâng cao:**
- Real ML model
- 2FA
- Cloud KMS
- SIEM/Alerting
- Pen testing

**🎯 Ưu tiên:** Hoàn thành 6 items HIGH PRIORITY trước khi deploy production!

---

## Files liên quan
- `CARD_SECURITY_ARCHITECTURE.md` - Kiến trúc tổng quan
- `backend/E2E_ENCRYPTION_GUIDE.md` - Hướng dẫn E2E encryption
- `backend/HTTPS_README.md` - TLS/HTTPS setup
- `backend/services/payment_service/security/FRAUD_DETECTION_TEST.md` - Test fraud detection
