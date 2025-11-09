# 🛡️ Fraud Detection System

## Tổng quan

Hệ thống phát hiện gian lận được tích hợp vào payment flow để **kiểm tra giao dịch TRƯỚC KHI gửi đến Stripe**, giúp:

- ✅ **Chặn giao dịch gian lận** trước khi xử lý thanh toán
- ✅ **Giảm chargeback** và tranh chấp từ khách hàng
- ✅ **Bảo vệ doanh nghiệp** khỏi tổn thất tài chính
- ✅ **Tuân thủ PCI-DSS** yêu cầu về fraud monitoring

---

## Kiến trúc

```
┌──────────────┐
│   Client     │
│  Checkout    │
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────┐
│     Payment Service                 │
│                                     │
│  1️⃣  Nhận thông tin giao dịch       │
│  2️⃣  Fraud Detection Check ◄─────┐ │
│  3️⃣  Nếu OK → Stripe API          │ │
│  4️⃣  Nếu Fraud → Chặn giao dịch   │ │
└────────────────────────────────┬───┘ │
                                 │     │
                        ┌────────▼─────▼───┐
                        │  FraudDetector   │
                        │                  │
                        │  • Business Rules│
                        │  • ML Scoring    │
                        │  • Risk Analysis │
                        └──────────────────┘
```

---

## Thành phần chính

### 1. **FraudDetector Class**
Vị trí: `backend/services/payment_service/security/fraud_detection.py`

**Chức năng:**
- Kiểm tra quy tắc nghiệp vụ (Business Rules)
- Chấm điểm gian lận bằng ML (Machine Learning Score)
- Kết hợp quy tắc + ML để ra quyết định cuối cùng

**Input:** `TransactionInput`
```python
{
    "user_id": "string",
    "amount": float,
    "currency": "vnd|usd",
    "ip_address": "123.45.67.89",
    "billing_country": "VN"  # ISO country code
}
```

**Output:** `FraudResult`
```python
{
    "is_fraud": bool,         # True = chặn, False = cho phép
    "score": 0.0-1.0,         # Điểm số gian lận (0-100%)
    "triggered_rules": [...], # Các quy tắc bị vi phạm
    "message": "string"       # Thông báo chi tiết
}
```

---

## Quy tắc phát hiện gian lận

### 🔴 **Quy tắc cứng (Hard Rules)** - Chặn ngay lập tức

#### 1. HIGH_RISK_COUNTRY
- **Điều kiện:** Quốc gia thanh toán nằm trong danh sách rủi ro cao
- **Danh sách:** `{"KP", "IR", "SY"}` (Triều Tiên, Iran, Syria)
- **Hành động:** Chặn giao dịch, `score = 1.0`
- **Message:** "Blocked due to high-risk country."

### 🟡 **Quy tắc mềm (Soft Rules)** - Tăng điểm nghi ngờ

#### 2. HIGH_VALUE_TRANSACTION
- **Điều kiện:** Giá trị giao dịch > 10,000 USD (hoặc tương đương)
- **Ngưỡng:** `HIGH_VALUE_THRESHOLD = 10000.00`
- **Hành động:** Tăng điểm lên ít nhất 0.75 (75%)
- **Message:** "Flagged for high value. Requires review."

#### 3. MISSING_IP_ADDRESS
- **Điều kiện:** Không có thông tin IP của người thanh toán
- **Hành động:** Đánh dấu cảnh báo (không tự động chặn)
- **Message:** Thêm vào `triggered_rules`

---

## Machine Learning Score

### Hiện tại (Placeholder)
- Trả về điểm số mặc định: `0.1` (10%)
- Ví dụ test: Nếu `amount > 5000` VÀ `ip = "1.2.3.4"` → `score = 0.9`

### Tích hợp ML thực tế (Tương lai)
```python
def _get_ml_score(self, transaction: TransactionInput) -> float:
    # 1. Load model đã huấn luyện
    # self.model = joblib.load('fraud_model.pkl')
    
    # 2. Feature engineering
    features = [
        transaction.amount,
        is_high_risk_country(transaction.billing_country),
        transaction_velocity_24h(transaction.user_id),
        device_fingerprint_match(transaction.ip_address),
        ...
    ]
    
    # 3. Dự đoán xác suất gian lận
    fraud_probability = self.model.predict_proba(features)[0][1]
    return fraud_probability
```

**Dataset cần thiết:**
- Giao dịch lịch sử (thành công + thất bại)
- Nhãn gian lận (fraud label): 0 = hợp lệ, 1 = gian lận
- Features: amount, country, IP, device, user history, velocity...

**Mô hình đề xuất:**
- XGBoost / LightGBM (hiệu quả cao)
- Random Forest (dễ giải thích)
- Neural Network (cho dữ liệu lớn)

---

## Tích hợp vào Payment Flow

### Code trong `payment.py`

```python
from backend.services.payment_service.security.fraud_detection import (
    FraudDetector,
    TransactionInput
)

# Khởi tạo detector khi service start
fraud_detector = FraudDetector()

@router.post("/create_payment")
async def create_payment(request: Request, ...):
    # 1. Lấy thông tin order
    order = get_order(order_id)
    
    # 2. Tạo transaction input
    fraud_check = TransactionInput(
        user_id=order_id,
        amount=float(order["amount"]) / 100,  # Convert VND
        currency=order["currency"],
        ip_address=request.client.host,
        billing_country="VN"  # Từ form hoặc user profile
    )
    
    # 3. Kiểm tra fraud
    fraud_result = fraud_detector.assess_transaction(fraud_check)
    
    # 4. Chặn nếu phát hiện gian lận
    if fraud_result.is_fraud:
        return error_page(f"⚠️ Transaction blocked: {fraud_result.message}")
    
    # 5. Nếu OK → Tiếp tục xử lý với Stripe
    stripe.PaymentIntent.create(...)
```

---

## Ngưỡng và cấu hình

### Trong `fraud_detection.py`

```python
# Quốc gia rủi ro cao
HIGH_RISK_COUNTRIES: Set[str] = {"KP", "IR", "SY"}

# Giá trị giao dịch cao (USD hoặc tương đương)
HIGH_VALUE_THRESHOLD: float = 10000.00

# Ngưỡng điểm số gian lận (85%)
FRAUD_SCORE_THRESHOLD: float = 0.85
```

### Tùy chỉnh ngưỡng

**Ví dụ: Giảm ngưỡng về 70% để chặn nhiều hơn**
```python
FRAUD_SCORE_THRESHOLD: float = 0.70  # Chặn chặt chẽ hơn
```

**Ví dụ: Tăng ngưỡng lên 95% để tránh false positive**
```python
FRAUD_SCORE_THRESHOLD: float = 0.95  # Chỉ chặn khi chắc chắn
```

---

## Kịch bản test

### Test 1: Giao dịch bình thường ✅
```python
tx = TransactionInput(
    user_id="user_123",
    amount=150.00,
    currency="vnd",
    ip_address="123.45.67.89",
    billing_country="VN"
)
result = detector.assess_transaction(tx)
# ✅ is_fraud=False, score=0.1, message="Transaction OK"
```

### Test 2: Giao dịch giá trị cao 🟡
```python
tx = TransactionInput(
    user_id="user_456",
    amount=25000.00,  # > 10,000 USD
    currency="usd",
    ip_address="10.0.0.1",
    billing_country="US"
)
result = detector.assess_transaction(tx)
# 🟡 is_fraud=False, score=0.75, message="Flagged for high value. Requires review."
```

### Test 3: Quốc gia rủi ro cao 🔴
```python
tx = TransactionInput(
    user_id="user_789",
    amount=50.00,
    currency="usd",
    ip_address="11.22.33.44",
    billing_country="KP"  # Triều Tiên
)
result = detector.assess_transaction(tx)
# 🔴 is_fraud=True, score=1.0, message="Blocked due to high-risk country."
```

---

## Logging và Monitoring

### Ghi log giao dịch bị chặn

**Khuyến nghị:** Lưu vào database hoặc file log
```python
if fraud_result.is_fraud:
    log_fraud_event({
        "timestamp": datetime.now(),
        "user_id": transaction.user_id,
        "amount": transaction.amount,
        "score": fraud_result.score,
        "rules": fraud_result.triggered_rules,
        "ip": transaction.ip_address
    })
```

### Metrics cần theo dõi
- **False Positive Rate:** % giao dịch hợp lệ bị chặn nhầm
- **False Negative Rate:** % giao dịch gian lận không bị phát hiện
- **Precision / Recall:** Độ chính xác của model
- **Fraud Rate:** % giao dịch gian lận trên tổng số giao dịch

---

## Mở rộng trong tương lai

### 1. Velocity Check
Kiểm tra số lần giao dịch trong khoảng thời gian ngắn
```python
def check_velocity(user_id: str) -> bool:
    # Số lần giao dịch của user trong 1 giờ qua
    count = db.count_transactions(user_id, last_hour=True)
    return count > 10  # Nghi ngờ nếu > 10 giao dịch/giờ
```

### 2. Device Fingerprinting
Nhận diện thiết bị bất thường
```python
def check_device(fingerprint: str, user_id: str) -> bool:
    known_devices = db.get_user_devices(user_id)
    return fingerprint not in known_devices
```

### 3. Email/Phone Verification
```python
def check_user_verified(user_id: str) -> bool:
    user = db.get_user(user_id)
    return user.email_verified and user.phone_verified
```

### 4. Behavioral Analysis
- Giờ giao dịch bất thường (3-5 AM)
- Mẫu mua hàng khác lạ so với lịch sử
- Địa chỉ IP khác quốc gia thường dùng

---

## Fail-Safe Mode

**Quan trọng:** Nếu fraud detector gặp lỗi, hệ thống sẽ:
- ✅ Cho phép giao dịch tiếp tục (fail-open mode)
- ⚠️ Ghi log lỗi để debug
- 📧 Gửi cảnh báo cho admin

```python
try:
    fraud_result = fraud_detector.assess_transaction(fraud_check)
    if fraud_result.is_fraud:
        return block_transaction()
except Exception as e:
    print(f"⚠️ Fraud detection error: {e}")
    # Không chặn giao dịch - tránh ảnh hưởng UX
```

---

## Tuân thủ PCI-DSS

Fraud detection giúp đáp ứng yêu cầu:
- **Requirement 11.4:** Monitor and test security controls
- **Requirement 12.10:** Incident response plan

**Cụ thể:**
- Log tất cả giao dịch bị chặn
- Review định kỳ false positive/negative
- Cập nhật quy tắc dựa trên mẫu tấn công mới

---

## FAQ

### Q1: Tại sao kiểm tra fraud TRƯỚC Stripe thay vì sau?
**A:** 
- Tiết kiệm phí Stripe (không bị charge cho giao dịch gian lận)
- Giảm tỷ lệ chargeback (ảnh hưởng đến account health)
- Phản hồi nhanh hơn cho người dùng

### Q2: Làm sao thêm quốc gia vào danh sách rủi ro cao?
**A:** Sửa trong `fraud_detection.py`:
```python
HIGH_RISK_COUNTRIES: Set[str] = {"KP", "IR", "SY", "AF", "IQ"}
```

### Q3: Có thể tắt fraud detection không?
**A:** Có, comment đoạn code trong `payment.py`:
```python
# fraud_result = fraud_detector.assess_transaction(fraud_check)
# if fraud_result.is_fraud:
#     return error_page(...)
```

### Q4: Làm sao train ML model?
**A:** 
1. Thu thập dataset (labeled transactions)
2. Feature engineering
3. Train model (XGBoost/Random Forest)
4. Evaluate (precision, recall, F1)
5. Replace placeholder trong `_get_ml_score()`

---

## Tài liệu tham khảo

- [Stripe Radar](https://stripe.com/docs/radar) - Fraud detection best practices
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [Scikit-learn Fraud Detection](https://scikit-learn.org/stable/auto_examples/applications/plot_outlier_detection_wine.html)
- [Kaggle Credit Card Fraud Dataset](https://www.kaggle.com/mlg-ulb/creditcardfraud)

---

## Liên hệ

Nếu có vấn đề hoặc câu hỏi về fraud detection system, vui lòng:
- 📧 Email: [your-email]
- 🐛 Issues: GitHub repository
- 📚 Docs: Xem file này và `fraud_detection.py`

