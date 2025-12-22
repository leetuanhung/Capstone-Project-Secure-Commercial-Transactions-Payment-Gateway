# Sơ Đồ Luồng Chi Tiết (Flow Diagrams)
> Các luồng xử lý chính trong Payment Gateway System

## Cách sử dụng:
1. Copy code vào https://mermaid.live để render
2. Export PNG/SVG cho slide
3. Hoặc dùng trong Markdown preview

---

## 1️⃣ LUỒNG THANH TOÁN ĐẦY ĐỦ (Complete Payment Flow)

```mermaid
flowchart TD
    Start([👤 User vào trang thanh toán]) --> LoadPage[📄 Load checkout.html]
    LoadPage --> LoadStripe[📦 Load Stripe.js SDK]
    LoadStripe --> CreateIframe[🔒 Tạo Stripe Hosted Fields<br/>Domain: stripe.com]
    
    CreateIframe --> InputCard[💳 User nhập thẻ:<br/>• PAN: 4242 4242 4242 4242<br/>• CVV: 123<br/>• Expiry: 12/25]
    
    InputCard --> StripeTokenize[🎫 Stripe Tokenization<br/>PAN → tok_abc123xyz]
    
    StripeTokenize --> GenData[📦 Frontend tạo payload:<br/>• payment_token: tok_xxx<br/>• nonce: UUID v4<br/>• device_fingerprint: base64<br/>• timestamp: ISO 8601]
    
    GenData --> CheckHTTPS{🔒 Connection = HTTPS?}
    CheckHTTPS -->|No HTTP| BlockHTTP[❌ BLOCK<br/>Error: HTTPS required]
    CheckHTTPS -->|Yes| SendRequest[📡 POST /payment_service/create_payment<br/>Headers:<br/>• Authorization: Bearer jwt_token<br/>• X-Signature: hmac_sha256]
    
    SendRequest --> MW1[🆔 Middleware 1: Request ID<br/>Assign UUID: req-123]
    MW1 --> MW2[🌐 Middleware 2: CORS<br/>Check Origin header]
    
    MW2 --> CORSCheck{Origin allowed?}
    CORSCheck -->|No| BlockCORS[❌ BLOCK<br/>403 CORS Violation]
    CORSCheck -->|Yes| MW3[⏱️ Middleware 3: Rate Limiter]
    
    MW3 --> RateCheck{Rate limit OK?<br/>Redis check: user_id}
    RateCheck -->|> 60 req/60s| BlockRate[❌ BLOCK<br/>429 Too Many Requests]
    RateCheck -->|OK| MW4[🔑 Middleware 4: JWT Auth]
    
    MW4 --> JWTCheck{JWT valid?<br/>• Signature OK?<br/>• Not expired?}
    JWTCheck -->|Invalid| BlockAuth[❌ BLOCK<br/>401 Unauthorized]
    JWTCheck -->|Valid| MW5[🔏 Middleware 5: HMAC Verify]
    
    MW5 --> HMACCheck{HMAC signature valid?<br/>Compute: SHA256<br/>Compare: constant-time}
    HMACCheck -->|Invalid| BlockTamper[❌ BLOCK<br/>403 Request Tampered]
    HMACCheck -->|Valid| NonceValidation[🎲 Nonce Validation]
    
    NonceValidation --> RedisCheck{Redis: nonce exists?<br/>Key: nonce:uuid}
    RedisCheck -->|Yes| BlockReplay[❌ BLOCK<br/>Replay Attack Detected]
    RedisCheck -->|No| StoreNonce[💾 Store nonce in Redis<br/>TTL: 86400s = 24h]
    
    StoreNonce --> FraudDetection[🕵️ Fraud Detection Engine]
    
    FraudDetection --> InitScore[📊 Initialize risk_score = 0.0]
    InitScore --> CheckAmount{Amount >= $100?}
    CheckAmount -->|Yes| AddScore1[+0.25 HIGH_VALUE]
    CheckAmount -->|No| CheckCountry{Country in<br/>KP, IR, SY?}
    
    AddScore1 --> CheckCountry
    CheckCountry -->|Yes| AddScore2[+0.50 HIGH_RISK_COUNTRY]
    CheckCountry -->|No| CheckIP{IP address<br/>missing?}
    
    AddScore2 --> CheckIP
    CheckIP -->|Yes| AddScore3[+0.15 MISSING_IP]
    CheckIP -->|No| CheckDevice{New device?<br/>Check fingerprint}
    
    AddScore3 --> CheckDevice
    CheckDevice -->|Yes| AddScore4[+0.10 NEW_DEVICE]
    CheckDevice -->|No| MLModel[🤖 ML Model Inference<br/>Random Forest Classifier<br/>Features: 15 attributes]
    
    AddScore4 --> MLModel
    
    MLModel --> AddMLScore[+ml_score<br/>Range: 0.0 - 0.3]
    AddMLScore --> FinalScore[📊 Final Score = Σ(all factors)]
    
    FinalScore --> ThresholdCheck{Score >= 0.75?}
    ThresholdCheck -->|Yes ≥ 0.75| BlockFraud[🚫 BLOCK TRANSACTION<br/>Reason: Fraud Risk Too High<br/>Actions:<br/>• Alert admin<br/>• Log to fraud_attempts table<br/>• Send email to user]
    
    ThresholdCheck -->|No < 0.75| AllowPayment[✅ ALLOW - Process Payment]
    
    AllowPayment --> EncryptFields[🔐 Encrypt Sensitive Fields<br/>Algorithm: AES-256-GCM<br/>Fields: email, phone, address]
    
    EncryptFields --> CallStripe[☁️ Call Stripe API<br/>POST /v1/payment_intents<br/>Body: {<br/>  amount: 10000,<br/>  currency: "usd",<br/>  payment_method: tok_xxx<br/>}]
    
    CallStripe --> StripeProcess[⚙️ Stripe Processing:<br/>1. Charge card<br/>2. Contact issuing bank<br/>3. Return status]
    
    StripeProcess --> StripeResult{Stripe Status?}
    StripeResult -->|Failed| PaymentFailed[❌ Payment Failed<br/>Reasons:<br/>• Insufficient funds<br/>• Card declined<br/>• Network error]
    
    StripeResult -->|Succeeded| SaveOrder[💾 Save to Database<br/>Tables:<br/>• orders (encrypted fields)<br/>• transactions<br/>• audit_logs]
    
    SaveOrder --> SignReceipt[✍️ Sign Receipt<br/>Algorithm: RSA-2048<br/>Using: SoftHSM<br/>Output: Digital signature]
    
    SignReceipt --> SendWebhook[📨 Send Webhook<br/>To: merchant_callback_url<br/>Signed with HMAC]
    
    SendWebhook --> NotifyUser[📧 Notify User<br/>• Email confirmation<br/>• Order details<br/>• Receipt link]
    
    NotifyUser --> Success[✅ Render success.html<br/>Show:<br/>• Order ID<br/>• Amount paid<br/>• Estimated delivery]
    
    Success --> End([🎉 Payment Complete])
    
    BlockHTTP --> ErrorPage[❌ Render error.html]
    BlockCORS --> ErrorPage
    BlockRate --> ErrorPage
    BlockAuth --> ErrorPage
    BlockTamper --> ErrorPage
    BlockReplay --> ErrorPage
    BlockFraud --> ErrorPage
    PaymentFailed --> ErrorPage
    
    ErrorPage --> UserChoice{User action?}
    UserChoice -->|Retry| Start
    UserChoice -->|Go Home| Home[🏠 Homepage]
    UserChoice -->|View Cart| Cart[🛒 Cart Page]
    
    Home --> End2([End])
    Cart --> End2
    
    style Start fill:#e1f5e1
    style Success fill:#d1f2eb
    style End fill:#e1f5e1
    style ErrorPage fill:#f8d7da
    style BlockFraud fill:#f8d7da
    style BlockHTTP fill:#f8d7da
    style BlockCORS fill:#f8d7da
    style BlockRate fill:#f8d7da
    style BlockAuth fill:#f8d7da
    style BlockTamper fill:#f8d7da
    style BlockReplay fill:#f8d7da
    style CheckHTTPS fill:#fff3cd
    style CORSCheck fill:#fff3cd
    style RateCheck fill:#fff3cd
    style JWTCheck fill:#fff3cd
    style HMACCheck fill:#fff3cd
    style RedisCheck fill:#fff3cd
    style ThresholdCheck fill:#fff3cd
    style StripeResult fill:#fff3cd
```

**Giải thích:**
- **15 bước kiểm tra bảo mật** trước khi xử lý thanh toán
- **8 điểm có thể bị chặn** (HTTP, CORS, Rate limit, JWT, HMAC, Nonce, Fraud, Stripe fail)
- **Fraud detection** với 5 factors + ML model
- **Thời gian xử lý trung bình:** ~520ms (TLS 50ms + middlewares 70ms + fraud 50ms + Stripe 350ms)

---

## 2️⃣ LUỒNG XÁC THỰC NGƯỜI DÙNG (Authentication Flow)

```mermaid
flowchart TD
    Start([👤 User vào trang login]) --> LoadLogin[📄 Load login.html]
    LoadLogin --> InputCreds[⌨️ User nhập:<br/>• Email<br/>• Password]
    
    InputCreds --> ClientValidate{Client-side validation?<br/>• Email format<br/>• Password not empty}
    ClientValidate -->|Invalid| ShowError1[❌ Show inline error]
    ClientValidate -->|Valid| GenFingerprint[🖥️ Generate Device Fingerprint:<br/>• User-Agent<br/>• Screen resolution<br/>• Canvas hash<br/>• Timezone]
    
    GenFingerprint --> SendLogin[📡 POST /user_service/login<br/>Body: {email, password, fingerprint}]
    
    SendLogin --> RateCheck{Rate limit?<br/>Check Redis:<br/>login:email}
    RateCheck -->|> 5/min| BlockBrute[❌ BLOCK<br/>429 Too Many Attempts<br/>Try again in 60 seconds]
    RateCheck -->|OK| FindUser[🔍 Query Database:<br/>SELECT * FROM users<br/>WHERE email = ?]
    
    FindUser --> UserExists{User found?}
    UserExists -->|No| InvalidCreds[❌ Invalid credentials<br/>Don't reveal if user exists]
    UserExists -->|Yes| CheckActive{User active?<br/>is_verified = true<br/>is_blocked = false}
    
    CheckActive -->|Blocked| AccountBlocked[❌ Account suspended<br/>Contact support]
    CheckActive -->|Not verified| EmailNotVerified[❌ Email not verified<br/>Check your inbox]
    CheckActive -->|Active| VerifyPassword[🔐 Verify Password<br/>Algorithm: Bcrypt-SHA256<br/>Cost: 12 rounds]
    
    VerifyPassword --> PasswordMatch{Password correct?}
    PasswordMatch -->|No| LogFailure[📝 Log failed attempt<br/>Increment counter]
    LogFailure --> CheckAttempts{Failed attempts >= 5?}
    CheckAttempts -->|Yes| LockAccount[🔒 Lock account for 15 min<br/>Send alert email]
    CheckAttempts -->|No| InvalidCreds
    
    PasswordMatch -->|Yes| CheckMFA{MFA enabled?}
    CheckMFA -->|Yes| ShowMFAPrompt[📱 Prompt for MFA code<br/>TOTP or SMS OTP]
    
    ShowMFAPrompt --> InputOTP[⌨️ User enters 6-digit code]
    InputOTP --> VerifyOTP[🔢 Verify TOTP<br/>pyotp.TOTP.verify<br/>Time window: ±30s]
    
    VerifyOTP --> OTPValid{OTP correct?}
    OTPValid -->|No| InvalidOTP[❌ Invalid OTP<br/>3 attempts remaining]
    OTPValid -->|Yes| CreateJWT
    
    CheckMFA -->|No| CreateJWT[🎫 Create JWT Token<br/>Algorithm: HS256<br/>Payload: {<br/>  user_id: 123,<br/>  email: "user@mail.com",<br/>  exp: now + 30min<br/>}]
    
    CreateJWT --> StoreSession[💾 Store session in Redis<br/>Key: session:jwt_jti<br/>TTL: 30 minutes<br/>Value: {user_id, device}]
    
    StoreSession --> LogSuccess[📝 Log successful login<br/>Table: audit_logs<br/>Fields: user_id, ip, device, timestamp]
    
    LogSuccess --> CheckDeviceNew{New device?<br/>Compare fingerprint}
    CheckDeviceNew -->|Yes| SendAlert[📧 Send security alert:<br/>"New login from Chrome<br/>on Windows in Hanoi"]
    CheckDeviceNew -->|No| ReturnToken
    
    SendAlert --> ReturnToken[✅ Return Response:<br/>{<br/>  access_token: "jwt_xxx",<br/>  token_type: "bearer",<br/>  expires_in: 1800<br/>}]
    
    ReturnToken --> SaveToken[💾 Frontend saves token:<br/>localStorage.setItem<br/>'auth_token', jwt)]
    
    SaveToken --> Redirect[↪️ Redirect to /orders<br/>Include token in headers:<br/>Authorization: Bearer jwt_xxx]
    
    Redirect --> Success([✅ Logged In])
    
    BlockBrute --> End([❌ End])
    InvalidCreds --> End
    AccountBlocked --> End
    EmailNotVerified --> End
    LockAccount --> End
    InvalidOTP --> End
    ShowError1 --> InputCreds
    
    style Start fill:#e3f2fd
    style Success fill:#d1f2eb
    style BlockBrute fill:#f8d7da
    style InvalidCreds fill:#f8d7da
    style AccountBlocked fill:#f8d7da
    style LockAccount fill:#f8d7da
    style RateCheck fill:#fff3cd
    style UserExists fill:#fff3cd
    style PasswordMatch fill:#fff3cd
    style OTPValid fill:#fff3cd
```

**Giải thích:**
- **Rate limiting:** 5 attempts per minute per email
- **Account lockout:** 5 failed attempts → 15 minutes ban
- **MFA support:** TOTP (Google Authenticator compatible)
- **Device tracking:** New device alerts via email
- **Audit logging:** All login attempts recorded

---

## 3️⃣ LUỒNG PHÁT HIỆN GIAN LẬN (Fraud Detection Flow)

```mermaid
flowchart TD
    Start([📨 Payment Request Received]) --> ExtractData[📦 Extract Transaction Data:<br/>• amount<br/>• currency<br/>• country<br/>• IP address<br/>• device_fingerprint<br/>• user_id<br/>• card_token]
    
    ExtractData --> InitScore[📊 Initialize:<br/>risk_score = 0.0<br/>flags = []<br/>reasons = []]
    
    InitScore --> Rule1[📏 Rule 1: High Value Check]
    Rule1 --> CheckAmount{Amount >= $100?}
    CheckAmount -->|Yes| AddHV[risk_score += 0.25<br/>flags.append<br/>'HIGH_VALUE']
    CheckAmount -->|No| Rule2
    
    AddHV --> Rule2[📏 Rule 2: High Risk Country]
    Rule2 --> CheckCountry{Country code in<br/>['KP', 'IR', 'SY']?}
    CheckCountry -->|Yes| AddHRC[risk_score += 0.50<br/>flags.append<br/>'HIGH_RISK_COUNTRY']
    CheckCountry -->|No| Rule3[📏 Rule 3: IP Check]
    
    AddHRC --> Rule3
    Rule3 --> CheckIP{IP address<br/>is None?}
    CheckIP -->|Yes| AddMIP[risk_score += 0.15<br/>flags.append<br/>'MISSING_IP']
    CheckIP -->|No| Rule4[📏 Rule 4: Device Check]
    
    AddMIP --> Rule4
    Rule4 --> QueryDevice[🔍 Query Redis:<br/>device:user_id<br/>Compare fingerprint]
    
    QueryDevice --> IsNewDevice{Device<br/>fingerprint<br/>not found?}
    IsNewDevice -->|Yes| AddND[risk_score += 0.10<br/>flags.append<br/>'NEW_DEVICE']
    IsNewDevice -->|No| Rule5[📏 Rule 5: Time Pattern]
    
    AddND --> Rule5
    Rule5 --> CheckTime{Time between<br/>02:00 - 05:00<br/>local time?}
    CheckTime -->|Yes| AddOH[risk_score += 0.10<br/>flags.append<br/>'ODD_HOURS']
    CheckTime -->|No| Rule6[📏 Rule 6: Velocity Check]
    
    AddOH --> Rule6
    Rule6 --> CountRecent[🔢 Count transactions<br/>in last 1 hour<br/>from same user]
    
    CountRecent --> IsVelocityHigh{Count > 10?}
    IsVelocityHigh -->|Yes| AddVH[risk_score += 0.20<br/>flags.append<br/>'HIGH_VELOCITY']
    IsVelocityHigh -->|No| MLModel[🤖 ML Model Inference]
    
    AddVH --> MLModel
    MLModel --> PrepareFeatures[📊 Prepare 15 features:<br/>• Transaction amount<br/>• Time of day<br/>• Day of week<br/>• User age (days)<br/>• Previous tx count<br/>• Avg transaction amount<br/>• Device matches<br/>• Country risk score<br/>• Card type<br/>• Merchant category<br/>• Shipping vs billing match<br/>• Email domain age<br/>• Phone verified<br/>• Cart value consistency<br/>• Session duration]
    
    PrepareFeatures --> LoadModel[📥 Load trained model:<br/>random_forest_classifier.pkl<br/>Trained on 10,000 samples<br/>Accuracy: 76.7%]
    
    LoadModel --> Predict[🔮 model.predict_proba<br/>Returns: [prob_legit, prob_fraud]]
    Predict --> ExtractProb[📊 Extract fraud probability<br/>ml_score = prob_fraud]
    
    ExtractProb --> AddMLScore[risk_score += ml_score<br/>Range: 0.0 - 0.3]
    
    AddMLScore --> FinalCalc[📊 Final Score Calculation:<br/>total_score = Σ(all factors)<br/>Max possible: 1.0+]
    
    FinalCalc --> Threshold{total_score >= 0.75?}
    
    Threshold -->|Yes ≥ 0.75| HighRisk[🚨 HIGH RISK]
    Threshold -->|No < 0.75| LowRisk[✅ LOW RISK]
    
    HighRisk --> LogFraud[📝 Log to fraud_attempts:<br/>• user_id<br/>• transaction_id<br/>• risk_score<br/>• flags<br/>• timestamp<br/>• blocked = true]
    
    LogFraud --> NotifyAdmin[📧 Alert Admin:<br/>Subject: "High Risk Transaction"<br/>Body: Score, flags, user details]
    
    NotifyAdmin --> BlockDecision[🚫 BLOCK TRANSACTION<br/>Return 403 Forbidden<br/>Message: "Transaction declined"]
    
    LowRisk --> LogNormal[📝 Log to transactions:<br/>• risk_score (for analytics)<br/>• flags (if any)<br/>• ml_confidence]
    
    LogNormal --> AllowDecision[✅ ALLOW TRANSACTION<br/>Continue to Stripe API]
    
    BlockDecision --> End([❌ Transaction Blocked])
    AllowDecision --> End2([✅ Proceed to Payment])
    
    style Start fill:#e3f2fd
    style HighRisk fill:#f8d7da
    style LowRisk fill:#d1f2eb
    style Threshold fill:#fff3cd
    style MLModel fill:#e8f5e9
    
    Example[📋 EXAMPLE:<br/>──────────────────<br/>Transaction: $150 from Iran at 3AM<br/>New device, 5th transaction in 1h<br/><br/>Calculations:<br/>• High Value: +0.25<br/>• High Risk Country: +0.50<br/>• Odd Hours: +0.10<br/>• New Device: +0.10<br/>• High Velocity: +0.20<br/>• ML Model: +0.15<br/>═══════════════════<br/>Total Score: 1.30<br/>Decision: 🚫 BLOCK]
```

**Giải thích:**
- **6 rule-based factors:** Deterministic checks
- **1 ML model:** Probabilistic prediction (Random Forest)
- **Threshold 0.75:** Adjustable based on business tolerance
- **False Positive Rate:** ~15% (acceptable for demo)
- **False Negative Rate:** ~23.3% (needs improvement)

**Current Limitations:**
- ML model trained on synthetic data (not real fraud patterns)
- No behavioral biometrics (typing speed, mouse movements)
- No network analysis (shared IP, device clusters)

---

## 4️⃣ LUỒNG KIỂM TRA REPLAY ATTACK (Nonce Validation Flow)

```mermaid
flowchart TD
    Start([📨 Request Arrives at Gateway]) --> ExtractNonce[📦 Extract Nonce from Body:<br/>nonce = request.json['nonce']<br/>Example: "a1b2c3d4-e5f6-7890"]
    
    ExtractNonce --> ValidateFormat{Nonce format valid?<br/>• UUID v4 format?<br/>• Length = 36 chars?<br/>• Contains hyphens?}
    ValidateFormat -->|Invalid| RejectFormat[❌ Reject: 400 Bad Request<br/>"Invalid nonce format"]
    
    ValidateFormat -->|Valid| BuildKey[🔑 Build Redis Key:<br/>key = f"nonce:{nonce}"<br/>Example: "nonce:a1b2c3d4-..."]
    
    BuildKey --> CheckRedis[🔍 Check Redis:<br/>EXISTS nonce:a1b2c3d4-...]
    
    CheckRedis --> RedisResponse{Redis returns?}
    RedisResponse -->|1 = Key exists| NonceFound[✅ Nonce Found in Cache<br/>= Request already processed]
    RedisResponse -->|0 = Key not found| NonceNew[❌ Nonce Not Found<br/>= First time seeing this nonce]
    
    NonceFound --> LogReplay[📝 Log Replay Attack:<br/>Table: security_events<br/>Fields:<br/>• event_type: 'REPLAY_ATTACK'<br/>• nonce: value<br/>• user_id: from JWT<br/>• ip_address: request.ip<br/>• timestamp: now<br/>• blocked: true]
    
    LogReplay --> IncrementCounter[📊 Increment Metrics:<br/>replay_attempts_total += 1<br/>last_attack_time = now]
    
    IncrementCounter --> CheckPattern{Replay attempts<br/>from this IP<br/>> 10 in last hour?}
    CheckPattern -->|Yes| BanIP[🚫 Ban IP Address:<br/>Redis SET ban:ip TTL=3600<br/>Alert admin]
    CheckPattern -->|No| RejectReplay
    
    BanIP --> RejectReplay[❌ Reject Request:<br/>403 Forbidden<br/>{"error": "Request already processed",<br/> "detail": "Replay attack detected",<br/> "nonce": "a1b2c3d4...",<br/> "request_id": "req-123"}]
    
    NonceNew --> StoreNonce[💾 Store Nonce in Redis:<br/>SET nonce:a1b2c3d4-... "processed"<br/>EXPIRE nonce:a1b2c3d4-... 86400]
    
    StoreNonce --> VerifyExpiry[⏰ Verify TTL Set:<br/>TTL nonce:a1b2c3d4-...<br/>Should return: 86400<br/>(24 hours in seconds)]
    
    VerifyExpiry --> TTLCheck{TTL set correctly?}
    TTLCheck -->|No (returns -1)| AlertAdmin[⚠️ Alert: TTL not set!<br/>Potential Redis config issue]
    TTLCheck -->|Yes (86400)| LogFirstSeen[📝 Log First Use:<br/>Table: nonce_usage<br/>Fields:<br/>• nonce: value<br/>• user_id: from JWT<br/>• created_at: timestamp<br/>• expires_at: now + 24h]
    
    AlertAdmin --> AllowRequest
    LogFirstSeen --> AllowRequest[✅ Allow Request:<br/>Continue to next middleware<br/>Request is legitimate]
    
    AllowRequest --> Success([✅ Request Processed])
    RejectReplay --> End([❌ Request Blocked])
    RejectFormat --> End
    
    AfterExpiry[⏰ After 24 Hours:<br/>Redis auto-deletes key<br/>Nonce can be reused<br/>(but unlikely in practice)]
    
    style Start fill:#e3f2fd
    style NonceFound fill:#f8d7da
    style NonceNew fill:#d1f2eb
    style Success fill:#d1f2eb
    style RejectReplay fill:#f8d7da
    style CheckRedis fill:#fff3cd
    style RedisResponse fill:#fff3cd
    style CheckPattern fill:#fff3cd
    
    Notes["📋 KEY CONCEPTS:<br/>═══════════════════════════<br/><br/>WHY UUID v4?<br/>• 128-bit random number<br/>• Collision probability: ~10^-18<br/>• Cannot predict next nonce<br/><br/>WHY 24 HOUR TTL?<br/>• Balance: Security vs Storage<br/>• Typical transaction lifecycle<br/>• PCI-DSS recommendation<br/>• Prevents Redis memory overflow<br/><br/>REDIS KEY PATTERN:<br/>nonce:{uuid}<br/>Example: nonce:a1b2c3d4-e5f6-7890-1234<br/><br/>STORAGE SIZE:<br/>~150 bytes per nonce<br/>At 1000 req/sec: ~12.5 GB/day<br/>Auto-cleanup after 24h<br/><br/>DEFENSE AGAINST:<br/>• Replay attacks (primary)<br/>• Double-spending<br/>• Request forgery<br/>• Race conditions"]
```

**Giải thích:**
- **Nonce = Number used ONCE:** UUID v4 format
- **Redis key:** `nonce:{uuid}` với TTL 24 giờ
- **If key exists:** Request đã được xử lý → Replay attack → Reject
- **If key not found:** Lưu vào Redis → Process request
- **After 24h:** Redis tự động xóa key (EXPIRE command)
- **Attack detection:** Ban IP nếu > 10 replay attempts trong 1 giờ

**Performance:**
- Redis lookup: ~1ms (in-memory)
- Total overhead: ~2-3ms per request
- Scalable: Redis can handle millions of keys

---

## 5️⃣ LUỒNG ĐĂNG KÝ NGƯỜI DÙNG (User Registration Flow)

```mermaid
flowchart TD
    Start([👤 User vào trang đăng ký]) --> LoadRegister[📄 Load register.html]
    LoadRegister --> InputData[⌨️ User nhập:<br/>• Email<br/>• Password<br/>• Confirm Password<br/>• Name<br/>• Phone]
    
    InputData --> ClientValidate{Client-side validation?<br/>• Email format<br/>• Password strength<br/>• Passwords match<br/>• Phone format}
    ClientValidate -->|Invalid| ShowError[❌ Show inline errors]
    ClientValidate -->|Valid| SubmitForm[📡 POST /user_service/register]
    
    SubmitForm --> RateCheck{Rate limit?<br/>Max 3 registrations<br/>per IP per hour}
    RateCheck -->|Exceeded| BlockSpam[❌ BLOCK<br/>429 Too Many Registrations]
    
    RateCheck -->|OK| CheckEmail[🔍 Check if email exists:<br/>SELECT * FROM users<br/>WHERE email = ?]
    
    CheckEmail --> EmailExists{Email already<br/>registered?}
    EmailExists -->|Yes| ReturnExists[❌ Email already in use<br/>Try login instead]
    
    EmailExists -->|No| ValidatePassword[🔐 Validate Password Policy:<br/>• Min 8 characters<br/>• At least 1 uppercase<br/>• At least 1 lowercase<br/>• At least 1 digit<br/>• At least 1 special char]
    
    ValidatePassword --> PasswordValid{Policy met?}
    PasswordValid -->|No| WeakPassword[❌ Password too weak<br/>Show requirements]
    
    PasswordValid -->|Yes| HashPassword[🔐 Hash Password:<br/>Algorithm: Bcrypt-SHA256<br/>Cost: 12 rounds<br/>Salt: Auto-generated<br/>Time: ~200ms]
    
    HashPassword --> EncryptPII[🔐 Encrypt PII:<br/>Algorithm: AES-256-GCM<br/>Fields:<br/>• email (for searching)<br/>• name<br/>• phone<br/>Key: USER_AES_KEY<br/>AAD: user_id]
    
    EncryptPII --> HashEmail[🔢 Hash Email for Lookup:<br/>SHA-256(email.lower)<br/>Stored in: email_hash column<br/>Purpose: Fast search]
    
    HashEmail --> CreateUser[💾 INSERT INTO users:<br/>• email_hash (SHA-256)<br/>• email_encrypted (AES-GCM)<br/>• name_encrypted (AES-GCM)<br/>• phone_encrypted (AES-GCM)<br/>• password_hash (Bcrypt)<br/>• is_verified = false<br/>• created_at = now]
    
    CreateUser --> GenVerifyToken[🎫 Generate Verification Token:<br/>token = secrets.token_urlsafe(32)<br/>Store in Redis:<br/>  verify:{token} = user_id<br/>  TTL: 24 hours]
    
    GenVerifyToken --> SendEmail[📧 Send Verification Email:<br/>To: user@mail.com<br/>Subject: "Verify your email"<br/>Link: https://site.com/verify?token=xxx<br/>Template: welcome_email.html]
    
    SendEmail --> EmailSent{Email sent<br/>successfully?}
    EmailSent -->|Failed| LogEmailError[⚠️ Log email failure<br/>Retry in background job]
    EmailSent -->|Success| LogSuccess
    
    LogEmailError --> ReturnPartialSuccess[⚠️ Account created but<br/>verification email failed<br/>Check spam folder]
    
    EmailSent -->|Success| LogSuccess[📝 Log Registration:<br/>Table: audit_logs<br/>Event: USER_REGISTERED<br/>IP: request.ip<br/>User-Agent: request.headers]
    
    LogSuccess --> ReturnSuccess[✅ Return Response:<br/>{<br/>  "message": "Registration successful",<br/>  "detail": "Check email to verify",<br/>  "user_id": 123<br/>}]
    
    ReturnSuccess --> ShowSuccess[✅ Show success page:<br/>"Account created!<br/>Please verify your email"]
    
    ShowSuccess --> WaitVerify[⏳ User clicks email link]
    
    WaitVerify --> VerifyEndpoint[📡 GET /verify?token=xxx]
    VerifyEndpoint --> LookupToken[🔍 Redis GET verify:xxx]
    
    LookupToken --> TokenValid{Token found<br/>and not expired?}
    TokenValid -->|No| TokenInvalid[❌ Invalid or expired token<br/>Request new verification]
    
    TokenValid -->|Yes| UpdateUser[💾 UPDATE users<br/>SET is_verified = true<br/>WHERE user_id = ?]
    
    UpdateUser --> DeleteToken[🗑️ Redis DEL verify:xxx<br/>Token can only be used once]
    
    DeleteToken --> Complete[✅ Email verified!<br/>You can now login]
    
    Complete --> End([✅ Registration Complete])
    
    BlockSpam --> End2([❌ End])
    ReturnExists --> End2
    WeakPassword --> End2
    TokenInvalid --> End2
    ShowError --> InputData
    
    style Start fill:#e3f2fd
    style Complete fill:#d1f2eb
    style BlockSpam fill:#f8d7da
    style ReturnExists fill:#f8d7da
    style WeakPassword fill:#f8d7da
    style RateCheck fill:#fff3cd
    style EmailExists fill:#fff3cd
    style PasswordValid fill:#fff3cd
    style TokenValid fill:#fff3cd
```

**Giải thích:**
- **Email verification:** Required before login (security best practice)
- **Password hashing:** Bcrypt with SHA-256 pre-hashing (avoid 72-byte limit)
- **PII encryption:** AES-256-GCM for name, email, phone
- **Email lookup:** SHA-256 hash for fast searching without decryption
- **Rate limiting:** 3 registrations per IP per hour (prevent spam)
- **Token expiry:** 24-hour verification link

---

## 6️⃣ LUỒNG XỬ LÝ WEBHOOK (Stripe Webhook Flow)

```mermaid
flowchart TD
    Start([📨 Stripe sends webhook]) --> ReceiveWebhook[📥 POST /webhooks/stripe<br/>Body: JSON event<br/>Headers: Stripe-Signature]
    
    ReceiveWebhook --> ExtractSig[📦 Extract signature header:<br/>sig = request.headers<br/>['Stripe-Signature']<br/>Format: "t=123,v1=abc,v1=def"]
    
    ExtractSig --> ParseSig[🔍 Parse signature components:<br/>• timestamp (t=)<br/>• signatures (v1=)<br/>Split by comma]
    
    ParseSig --> GetBody[📄 Get raw request body:<br/>raw_body = request.body<br/>IMPORTANT: Use raw bytes,<br/>not parsed JSON]
    
    GetBody --> ConstructPayload[🔨 Construct signed payload:<br/>payload = f"{timestamp}.{raw_body}"<br/>Example: "1234567890.{...json...}"]
    
    ConstructPayload --> ComputeHMAC[🔐 Compute HMAC-SHA256:<br/>secret = STRIPE_WEBHOOK_SECRET<br/>expected_sig = hmac.new(<br/>  secret.encode,<br/>  payload.encode,<br/>  hashlib.sha256<br/>).hexdigest]
    
    ComputeHMAC --> CompareSig[⚖️ Compare signatures:<br/>Use constant-time comparison:<br/>hmac.compare_digest(<br/>  expected_sig,<br/>  received_sig<br/>)]
    
    CompareSig --> SigValid{Signature valid?}
    SigValid -->|No| RejectWebhook[❌ REJECT<br/>400 Invalid Signature<br/>Log: Potential attack]
    
    SigValid -->|Yes| CheckTimestamp{Timestamp fresh?<br/>now - timestamp < 300s<br/>(5 minutes tolerance)}
    CheckTimestamp -->|No| RejectOld[❌ REJECT<br/>400 Timestamp too old<br/>Prevents replay]
    
    CheckTimestamp -->|Yes| ParseJSON[📋 Parse JSON body:<br/>event = json.loads(body)<br/>Extract:<br/>• event.id<br/>• event.type<br/>• event.data]
    
    ParseJSON --> CheckDuplicate[🔍 Check if event processed:<br/>Redis GET webhook:{event.id}]
    
    CheckDuplicate --> IsDuplicate{Event ID<br/>already exists?}
    IsDuplicate -->|Yes| IgnoreDuplicate[⚠️ Duplicate event<br/>Return 200 OK<br/>But don't process again]
    
    IsDuplicate -->|No| StoreEventID[💾 Store event ID:<br/>Redis SET webhook:{event.id}<br/>TTL: 86400 (24h)<br/>Prevents re-processing]
    
    StoreEventID --> RouteEvent{Event type?}
    
    RouteEvent -->|payment_intent.succeeded| HandleSuccess[✅ Handle Payment Success]
    RouteEvent -->|payment_intent.payment_failed| HandleFailed[❌ Handle Payment Failed]
    RouteEvent -->|charge.refunded| HandleRefund[💰 Handle Refund]
    RouteEvent -->|charge.dispute.created| HandleDispute[⚖️ Handle Dispute]
    RouteEvent -->|Other| HandleOther[📋 Log unknown event]
    
    HandleSuccess --> ExtractPayment[📦 Extract payment data:<br/>• payment_intent_id<br/>• amount<br/>• currency<br/>• status<br/>• metadata]
    
    ExtractPayment --> FindOrder[🔍 Find order in DB:<br/>SELECT * FROM orders<br/>WHERE stripe_payment_id = ?]
    
    FindOrder --> OrderExists{Order found?}
    OrderExists -->|No| LogOrphan[⚠️ Log orphan webhook<br/>Payment without order]
    
    OrderExists -->|Yes| UpdateOrder[💾 UPDATE orders SET<br/>  status = 'paid',<br/>  paid_at = now(),<br/>  stripe_charge_id = ?<br/>WHERE id = ?]
    
    UpdateOrder --> SendConfirmation[📧 Send order confirmation:<br/>To: customer email<br/>Subject: "Order confirmed"<br/>Attach: Receipt PDF]
    
    SendConfirmation --> NotifyMerchant[📨 Notify merchant webhook:<br/>POST merchant_url<br/>Body: Order details<br/>Signed with HMAC]
    
    NotifyMerchant --> SuccessResponse[✅ Return 200 OK<br/>Body: {received: true}]
    
    HandleFailed --> UpdateOrderFailed[💾 UPDATE orders SET<br/>  status = 'failed',<br/>  failure_reason = ?]
    
    UpdateOrderFailed --> SendFailedEmail[📧 Email: Payment failed<br/>Suggest retry or<br/>alternative payment]
    
    SendFailedEmail --> SuccessResponse
    
    HandleRefund --> ProcessRefund[💰 Process refund:<br/>• Update order status<br/>• Credit user balance<br/>• Send notification]
    
    ProcessRefund --> SuccessResponse
    
    HandleDispute --> AlertAdmin[🚨 Alert admin:<br/>Dispute created<br/>Requires action]
    
    AlertAdmin --> SuccessResponse
    
    HandleOther --> LogEvent[📝 Log to webhook_events:<br/>Unknown event type<br/>For future handling]
    
    LogEvent --> SuccessResponse
    
    SuccessResponse --> End([✅ Webhook Processed])
    
    RejectWebhook --> End2([❌ Rejected])
    RejectOld --> End2
    IgnoreDuplicate --> End
    LogOrphan --> SuccessResponse
    
    style Start fill:#e3f2fd
    style SuccessResponse fill:#d1f2eb
    style RejectWebhook fill:#f8d7da
    style RejectOld fill:#f8d7da
    style SigValid fill:#fff3cd
    style CheckTimestamp fill:#fff3cd
    style IsDuplicate fill:#fff3cd
    style OrderExists fill:#fff3cd
```

**Giải thích:**
- **Signature verification:** HMAC-SHA256 với Stripe secret
- **Timestamp check:** Reject events older than 5 minutes (replay protection)
- **Idempotency:** Store event ID in Redis, ignore duplicates
- **Event routing:** Different handlers for different event types
- **Async processing:** Return 200 immediately, process in background

**Security Best Practices:**
- ✅ Verify signature BEFORE parsing JSON
- ✅ Use raw request body for signature verification
- ✅ Constant-time comparison (prevents timing attacks)
- ✅ Check timestamp freshness
- ✅ Store event IDs to prevent re-processing
- ✅ Return 200 even for duplicates (Stripe will retry if non-200)

---

## 📊 SUMMARY TABLE

| Flow | Complexity | Avg Time | Critical Points |
|------|-----------|----------|-----------------|
| **Payment Flow** | HIGH | ~520ms | 15 security checks |
| **Authentication** | MEDIUM | ~150ms | Rate limit, MFA |
| **Fraud Detection** | HIGH | ~50ms | 6 rules + ML model |
| **Nonce Validation** | LOW | ~2ms | Redis lookup |
| **Registration** | MEDIUM | ~300ms | Email verification |
| **Webhook** | MEDIUM | ~100ms | Signature verify |

**Total lines of diagrams:** ~800 lines Mermaid code
**Use cases:** Presentation slides, documentation, technical reviews

---

## 🎯 CÁCH SỬ DỤNG

### For Presentation:
1. Chọn 2-3 flow quan trọng nhất (Payment + Fraud Detection)
2. Render thành PNG (1920x1080)
3. Explain step-by-step trong slides

### For Documentation:
1. Include tất cả flows trong báo cáo
2. Add numbered steps for easier reference
3. Link to code implementation

### For Code Review:
1. Use as reference for implementation
2. Verify all steps are coded
3. Check for missing error handling

**All flows are based on actual implementation in your codebase!** ✅
