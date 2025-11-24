# 🧪 HƯỚNG DẪN TEST MACHINE LEARNING FRAUD DETECTION

## ✅ Chuẩn bị

1. **Đã tạo model ML**: `fraud_model_mock.pkl`
2. **Đã thêm vào `.env`**: `FRAUD_MODEL_PATH=...`
3. **Restart server** để load model:
   ```powershell
   uvicorn backend.main:app --reload
   ```
4. **Kiểm tra log server** khi start — phải thấy:
   ```
   Fraud Detector: loaded ML model from D:\UIT\...\fraud_model_mock.pkl
   ```

---

## 📋 CÁC KỊCH BẢN TEST

### ✅ **SCENARIO 1: Giao dịch bình thường (PASS)**
**Mục tiêu**: Xác nhận giao dịch hợp lệ không bị block

**Điều kiện**:
- User đã có ít nhất 2-3 đơn hàng trước đó
- Số tiền giao dịch mới tương tự mức trung bình (ví dụ: avg=1500 VND, new=1500 VND)

**Cách test**:
1. Đăng nhập với user có lịch sử (hoặc tạo 2-3 đơn hàng nhỏ trước)
2. Checkout với `order_id=ORD-DEMO-01` (amount=150000 VND = 1500 VND trong DB)
3. Submit thanh toán

**Kết quả mong đợi**:
- ✅ Thanh toán thành công
- Log: `Fraud probability: < 75%`
- Order được lưu vào DB

---

### 🚨 **SCENARIO 2: Giao dịch đầu tiên với số tiền cao (BLOCK)**
**Mục tiêu**: ML phát hiện user mới tạo đơn hàng giá trị cao ngay lần đầu

**Điều kiện**:
- User **chưa có** đơn hàng nào trong DB (`cnt_30d = 0`)
- Số tiền > 2000 VND (trong DB, tương đương > 200,000 VND nếu currency=vnd)

**Cách test**:
1. Tạo user mới (đăng ký)
2. Đăng nhập
3. **Tạo một order test có amount cao**:
   - Sửa tạm trong `payment.py` → `MOCK_ORDERS`:
     ```python
     {"id": "ORD-HIGH-01", "description": "High Value Test", "amount": 250000, "currency": "vnd"}
     ```
   - Hoặc dùng cart với tổng > 200,000 VND
4. Checkout với order này

**Kết quả mong đợi**:
- 🚫 **Transaction bị BLOCK**
- Error page hiển thị: `⚠️ Transaction blocked: Blocked due to high fraud score (0.XX)`
- Log server:
  ```
  🚨 ML Rule 1: First transaction with high amount (2500)
  Fraud probability: 60.00%
  ```

---

### 🚨 **SCENARIO 3: Số tiền cao gấp 3 lần trung bình (BLOCK)**
**Mục tiêu**: ML phát hiện giao dịch bất thường so với lịch sử

**Điều kiện**:
- User có lịch sử đơn hàng với giá trị trung bình ~500 VND
- Giao dịch mới có amount >= 1500 VND (3x avg)

**Cách test**:
1. User đã có 3-4 đơn nhỏ (mỗi đơn ~50,000 VND = 500 VND trong DB)
2. Tạo order test amount=300,000 VND (3000 VND trong DB)
3. Checkout

**Kết quả mong đợi**:
- 🚫 **Transaction bị BLOCK**
- Log:
  ```
  🚨 ML Rule 2: Amount 3000 >> 3x avg 500
  Fraud probability: 40.00%
  ```

---

### 🚨 **SCENARIO 4: Giao dịch liên tiếp quá nhanh (BLOCK)**
**Mục tiêu**: ML phát hiện giao dịch spam/bot

**Điều kiện**:
- Thực hiện 2 giao dịch liên tiếp trong < 1 phút

**Cách test**:
1. Checkout và thanh toán thành công đơn thứ 1
2. **Ngay lập tức** (trong vòng 30-60 giây) checkout và submit đơn thứ 2

**Kết quả mong đợi**:
- 🚫 **Transaction thứ 2 bị BLOCK**
- Log:
  ```
  🚨 ML Rule 3: Rapid transaction (45s since last)
  Fraud probability: 30.00%
  ```

---

### 🚨 **SCENARIO 5: Quá nhiều giao dịch + số tiền cao (BLOCK)**
**Mục tiêu**: ML phát hiện pattern tổng hợp nhiều dấu hiệu gian lận

**Điều kiện**:
- User có > 10 đơn trong 7 ngày
- Giao dịch mới có amount > 5000 VND

**Cách test**:
1. Tạo 12 đơn hàng nhỏ trong 7 ngày (có thể dùng script để insert vào DB)
2. Checkout với order amount cao (> 500,000 VND)

**Kết quả mong đợi**:
- 🚫 **Transaction bị BLOCK**
- Log:
  ```
  🚨 ML Rule 2: Amount 6000 >> 3x avg 500
  🚨 ML Rule 4: Too many transactions in 7 days (12)
  🚨 ML Rule 5: Very high amount (6000)
  Fraud probability: 100.00%
  ```

---

## 🔍 CÁCH KIỂM TRA KẾT QUẢ

### 1. **Xem Log Server**
Khi submit payment, log sẽ hiển thị:
```
🚨 ML Rule X: [mô tả]
Fraud probability: XX.XX%
✅ User authenticated from form: id=1
⚠️ Transaction blocked: Blocked due to high fraud score (0.85)
```

### 2. **Kiểm tra DB**
```sql
-- Xem lịch sử đơn hàng của user
SELECT id, owner_id, total_price, status, created_at 
FROM orders 
WHERE owner_id = 1 
ORDER BY created_at DESC;

-- Tính trung bình và đếm đơn
SELECT 
    owner_id,
    COUNT(*) as total_orders,
    AVG(total_price) as avg_amount,
    MAX(total_price) as max_amount
FROM orders 
GROUP BY owner_id;
```

### 3. **Kiểm tra Error Page**
Nếu transaction bị block, user sẽ thấy trang error với message:
```
⚠️ Transaction blocked: Blocked due to high fraud score (0.XX)
```

---

## 🎯 NGƯỠNG FRAUD DETECTION

Model hiện tại sử dụng:
- **Ngưỡng block**: `fraud_score >= 0.75` (75%)
- Định nghĩa trong: `backend/services/payment_service/security/fraud_detection.py`
- Dòng: `FRAUD_SCORE_THRESHOLD: float = 0.75`

**Để điều chỉnh ngưỡng** (nếu muốn):
```python
# Trong fraud_detection.py
FRAUD_SCORE_THRESHOLD: float = 0.60  # Nghiêm ngặt hơn (block nhiều hơn)
# hoặc
FRAUD_SCORE_THRESHOLD: float = 0.85  # Lỏng hơn (block ít hơn)
```

---

## 📊 QUY TẮC ML HIỆN TẠI

Model mock áp dụng 5 rules:

| Rule | Điều kiện | Fraud Score | Mô tả |
|------|-----------|-------------|-------|
| 1 | `cnt_30d == 0 AND amount > 2000` | +0.6 | Giao dịch đầu tiên có giá trị cao |
| 2 | `amount > avg_amount * 3` | +0.4 | Số tiền cao gấp 3 lần trung bình |
| 3 | `last_order_seconds < 60` | +0.3 | Giao dịch liên tiếp < 1 phút |
| 4 | `cnt_7d > 10` | +0.2 | Quá nhiều giao dịch trong 7 ngày |
| 5 | `amount > 5000` | +0.5 | Số tiền quá cao |

**Điểm số tích lũy** → Nếu >= 0.75 → **BLOCK**

---

## 🛠️ TẠO DỮ LIỆU TEST (Nếu cần)

### Tạo nhiều đơn hàng test trong DB:
```sql
-- Tạo 12 đơn nhỏ cho user_id=1
INSERT INTO orders (owner_id, status, total_price, created_at) VALUES
(1, 'SUCCESS', 500, NOW() - INTERVAL '6 days'),
(1, 'SUCCESS', 600, NOW() - INTERVAL '5 days'),
(1, 'SUCCESS', 450, NOW() - INTERVAL '4 days'),
(1, 'SUCCESS', 550, NOW() - INTERVAL '3 days'),
(1, 'SUCCESS', 500, NOW() - INTERVAL '2 days'),
(1, 'SUCCESS', 480, NOW() - INTERVAL '1 day'),
(1, 'SUCCESS', 520, NOW() - INTERVAL '12 hours'),
(1, 'SUCCESS', 490, NOW() - INTERVAL '6 hours'),
(1, 'SUCCESS', 510, NOW() - INTERVAL '3 hours'),
(1, 'SUCCESS', 530, NOW() - INTERVAL '2 hours'),
(1, 'SUCCESS', 470, NOW() - INTERVAL '1 hour'),
(1, 'SUCCESS', 500, NOW() - INTERVAL '30 minutes');
```

---

## ✅ CHECKLIST TRƯỚC KHI TEST

- [ ] Model đã được tạo: `fraud_model_mock.pkl` tồn tại
- [ ] `.env` có `FRAUD_MODEL_PATH=...`
- [ ] Server đã restart và log hiển thị "Fraud Detector: loaded ML model..."
- [ ] User đã đăng nhập và `localStorage.getItem('user_id')` có giá trị
- [ ] Database có bảng `orders` và có thể query được

---

## 🎓 LƯU Ý

1. **Model hiện tại là MOCK** — logic đơn giản để demo. Model ML thật cần:
   - Huấn luyện trên dataset thực (transactions có label fraud/normal)
   - Feature engineering phức tạp hơn
   - Validation & testing trên test set

2. **Để sản xuất (production)**:
   - Dùng model như XGBoost, LightGBM, hoặc Neural Network
   - Thêm features: device fingerprint, IP geolocation, payment velocity, v.v.
   - Monitoring & retraining định kỳ

3. **Tính năng bổ sung có thể thêm**:
   - Manual review queue cho transactions có score 0.5-0.75
   - Email/SMS thông báo user khi transaction bị block
   - Admin dashboard để review flagged transactions
   - A/B testing fraud rules
