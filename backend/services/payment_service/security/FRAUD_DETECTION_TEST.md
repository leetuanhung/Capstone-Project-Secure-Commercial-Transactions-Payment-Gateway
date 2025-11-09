# 🧪 Test Fraud Detection

## Quick Test Guide

### 1️⃣ Kiểm tra Fraud Detector đã load
Khi chạy server, bạn sẽ thấy log:
```
Fraud Detector initialized.
```

### 2️⃣ Test bằng Python script
```bash
cd backend
python -c "from services.payment_service.security.fraud_detection import FraudDetector, TransactionInput; detector = FraudDetector(); tx = TransactionInput(user_id='test', amount=100, currency='vnd', ip_address='127.0.0.1', billing_country='VN'); result = detector.assess_transaction(tx); print(f'Fraud: {result.is_fraud}, Score: {result.score}')"
```

### 3️⃣ Test qua Payment Flow

#### ✅ Test giao dịch bình thường
1. Truy cập http://127.0.0.1:8000/orders
2. Thêm sản phẩm vào giỏ (giá < 10,000 USD)
3. Checkout và thanh toán
4. **Kỳ vọng:** Giao dịch THÀNH CÔNG

#### 🔴 Test chặn quốc gia rủi ro cao
Để test, bạn cần sửa tạm trong `payment.py`:
```python
# Dòng 183 - Thay "VN" bằng "KP" (Triều Tiên)
billing_country="KP"  # Test high-risk country
```

Sau đó thử thanh toán:
- **Kỳ vọng:** Trang lỗi với message "⚠️ Transaction blocked: Blocked due to high-risk country."

#### 🟡 Test giao dịch giá trị cao
1. Trong `order.py`, tạo order với amount > 1,000,000 VND (~ 10,000 USD)
2. Thử thanh toán order đó
3. **Kỳ vọng:** Điểm score tăng lên 0.75 (nếu không bị chặn bởi quy tắc khác)

### 4️⃣ Xem Fraud Logs

Khi fraud detector chặn giao dịch, bạn sẽ thấy trong terminal:
```
⚠️ Fraud detection error: [nếu có lỗi]
```

hoặc trong response:
```
⚠️ Transaction blocked: [lý do] (Score: [điểm])
```

### 5️⃣ Debug Mode

Thêm print statements trong `payment.py` để debug:
```python
# Sau dòng fraud_result = fraud_detector.assess_transaction(fraud_check)
print(f"🛡️ Fraud Check: is_fraud={fraud_result.is_fraud}, score={fraud_result.score}, rules={fraud_result.triggered_rules}")
```

### 6️⃣ Tùy chỉnh ngưỡng

Sửa trong `fraud_detection.py`:
```python
# Giảm ngưỡng để test dễ hơn
FRAUD_SCORE_THRESHOLD: float = 0.50  # 50% thay vì 85%

# Hoặc giảm ngưỡng giá trị cao
HIGH_VALUE_THRESHOLD: float = 100.00  # 100 USD thay vì 10,000
```

---

## Kết quả mong đợi

### Giao dịch bình thường (VN, 150,000 VND)
```json
{
  "is_fraud": false,
  "score": 0.1,
  "triggered_rules": [],
  "message": "Transaction OK"
}
```

### Giao dịch quốc gia rủi ro cao (KP, bất kỳ số tiền)
```json
{
  "is_fraud": true,
  "score": 1.0,
  "triggered_rules": ["HIGH_RISK_COUNTRY"],
  "message": "Blocked due to high-risk country."
}
```

### Giao dịch giá trị cao (US, 25,000 USD)
```json
{
  "is_fraud": false,
  "score": 0.75,
  "triggered_rules": ["HIGH_VALUE_TRANSACTION"],
  "message": "Flagged for high value. Requires review."
}
```

---

## Troubleshooting

### Lỗi: "FraudDetector not initialized"
- Kiểm tra import trong `payment.py`
- Đảm bảo `fraud_detector = FraudDetector()` được gọi khi service start

### Fraud detection không chặn gì cả
- Kiểm tra ngưỡng `FRAUD_SCORE_THRESHOLD` trong `fraud_detection.py`
- Kiểm tra quốc gia trong request (có trong danh sách `HIGH_RISK_COUNTRIES` không?)
- Kiểm tra amount đã được convert đúng chưa (VND → USD)

### Tất cả giao dịch bị chặn
- Ngưỡng quá thấp? Tăng `FRAUD_SCORE_THRESHOLD`
- Quốc gia bị nhầm? Kiểm tra `billing_country` value
- ML score quá cao? Check hàm `_get_ml_score()`

---

## Next Steps

1. ✅ Test basic fraud detection
2. 🔄 Thu thập transaction logs
3. 📊 Phân tích false positive/negative rate
4. 🤖 Train ML model với data thật
5. 📈 Monitor fraud rate trong production
