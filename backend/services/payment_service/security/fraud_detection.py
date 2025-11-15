# security/fraud_detection.py

from pydantic import BaseModel, Field
from typing import List, Set, Optional
import datetime

# --- Hằng số cho các quy tắc ---

# Danh sách các quốc gia bị coi là rủi ro cao (ví dụ)
# Bạn có thể tải danh sách này từ CSDL hoặc tệp cấu hình
HIGH_RISK_COUNTRIES: Set[str] = {"KP", "IR", "SY"} 

# Ngưỡng giá trị giao dịch cao
HIGH_VALUE_THRESHOLD: float = 1000000.00

# Ngưỡng điểm số
FRAUD_SCORE_THRESHOLD: float = 0.75 # 85%

# --- Cấu trúc dữ liệu (Sử dụng Pydantic) ---

class TransactionInput(BaseModel):
    """
    Dữ liệu đầu vào cho việc kiểm tra gian lận.
    Đây nên là dữ liệu TRƯỚC khi bạn gửi đến Stripe.
    """
    user_id: str
    amount: float = Field(..., gt=0) # gt=0 đảm bảo số tiền > 0
    currency: str = "vnd"
    ip_address: Optional[str] = None
    billing_country: Optional[str] = None # Mã quốc gia ISO (ví dụ: "VN", "US")
    # Thêm các trường khác nếu cần cho mô hình ML
    # ví dụ: email, số lần giao dịch trong 24h, v.v.


class FraudResult(BaseModel):
    """
    Kết quả trả về từ hệ thống phát hiện gian lận.
    """
    is_fraud: bool = False
    score: float = 0.0 # Điểm số gian lận (từ 0.0 đến 1.0)
    triggered_rules: List[str] = []
    message: str = "Transaction OK"


# --- Lớp dịch vụ phát hiện gian lận ---

class FraudDetector:
    """
    Kết hợp cả logic dựa trên quy tắc và chấm điểm ML
    """

    def __init__(self):
        # Ở đây bạn có thể tải mô hình ML đã huấn luyện
        # ví dụ: self.model = joblib.load('fraud_model.pkl')
        self.model = None # Tạm thời
        print("Fraud Detector initialized.")

    def _get_ml_score(self, transaction: TransactionInput) -> float:
        """
        Hàm (riêng tư) để chấm điểm bằng mô hình ML.
        Đây là phần giữ chỗ (placeholder).
        """
        if not self.model:
            # Nếu không có mô hình, trả về điểm số trung lập
            return 0.1 # Giả định điểm số thấp

        # --- Khi có mô hình thật ---
        # 1. Tiền xử lý dữ liệu (feature engineering)
        # features = self._preprocess_features(transaction)
        
        # 2. Dự đoán
        # (Lưu ý: self.model.predict_proba trả về [prob_class_0, prob_class_1])
        # score = self.model.predict_proba(features)[0][1] 
        # return score
        
        # Chỉ là ví dụ
        if transaction.amount > 5000 and transaction.ip_address == "1.2.3.4":
             return 0.9 # Điểm ML cao
        
        return 0.1 # Điểm ML thấp

    def _apply_business_rules(self, transaction: TransactionInput) -> List[str]:
        """
        Áp dụng các quy tắc nghiệp vụ cứng.
        """
        triggered = []

        # Quy tắc 1: Giao dịch giá trị cực cao
        if transaction.amount > HIGH_VALUE_THRESHOLD:
            triggered.append("HIGH_VALUE_TRANSACTION")

        # Quy tắc 2: Quốc gia rủi ro cao
        if transaction.billing_country and transaction.billing_country.upper() in HIGH_RISK_COUNTRIES:
            triggered.append("HIGH_RISK_COUNTRY")
            
        # Quy tắc 3: Thiếu thông tin IP (ví dụ)
        if not transaction.ip_address:
            triggered.append("MISSING_IP_ADDRESS")

        # Bạn có thể thêm nhiều quy tắc khác ở đây
        # ...

        return triggered

    def assess_transaction(self, transaction: TransactionInput) -> FraudResult:
        """
        Hàm chính để đánh giá một giao dịch.
        """
        
        # 1. Chạy các quy tắc nghiệp vụ
        triggered_rules = self._apply_business_rules(transaction)
        
        # 2. Chấm điểm bằng ML
        ml_score = self._get_ml_score(transaction)

        # 3. Tính toán điểm số cuối cùng và quyết định
        # Đây là một logic kết hợp đơn giản, bạn có thể điều chỉnh
        final_score = ml_score
        is_fraudulent = False
        message = "Transaction OK"

        if "HIGH_RISK_COUNTRY" in triggered_rules:
            # Quy tắc cứng: Tự động chặn
            is_fraudulent = True
            final_score = 1.0
            message = "Blocked due to high-risk country."
            
        elif "HIGH_VALUE_TRANSACTION" in triggered_rules:
            # Quy tắc mềm: Tăng điểm số
            final_score = max(final_score, 0.75) # Tăng điểm lên ít nhất 0.75
            message = "Flagged for high value. Requires review."

        # Kiểm tra ngưỡng cuối cùng
        if not is_fraudulent and final_score >= FRAUD_SCORE_THRESHOLD:
            is_fraudulent = True
            message = f"Blocked due to high fraud score ({final_score:.2f})."
        
        if is_fraudulent:
             # Đảm bảo điểm số phản ánh quyết định
             final_score = max(final_score, FRAUD_SCORE_THRESHOLD)

        return FraudResult(
            is_fraud=is_fraudulent,
            score=final_score,
            triggered_rules=triggered_rules,
            message=message
        )

# --- Cách sử dụng (Ví dụ) ---
# Bạn sẽ import FraudDetector và TransactionInput vào tệp main
# (ví dụ: backend/main.py từ tệp docker-compose.yml của bạn)

if __name__ == "__main__":
    # Chạy trực tiếp để kiểm tra
    detector = FraudDetector()

    # Kịch bản 1: Giao dịch bình thường
    tx_normal = TransactionInput(
        user_id="user_123",
        amount=150.00,
        currency="vnd",
        ip_address="123.45.67.89",
        billing_country="VN"
    )
    result_normal = detector.assess_transaction(tx_normal)
    print("--- Giao dịch bình thường ---")
    print(result_normal.json(indent=2))

    # Kịch bản 2: Giao dịch giá trị rất cao
    tx_high_value = TransactionInput(
        user_id="user_456",
        amount=25000.00, # Vượt ngưỡng 10,000
        currency="usd",
        ip_address="10.0.0.1",
        billing_country="US"
    )
    result_high = detector.assess_transaction(tx_high_value)
    print("\n--- Giao dịch giá trị cao ---")
    print(result_high.json(indent=2))
    
    # Kịch bản 3: Giao dịch từ quốc gia rủi ro cao
    tx_high_risk = TransactionInput(
        user_id="user_789",
        amount=50.00,
        currency="usd",
        ip_address="11.22.33.44",
        billing_country="KP" # Quốc gia rủi ro cao
    )
    result_risk = detector.assess_transaction(tx_high_risk)
    print("\n--- Giao dịch rủi ro cao ---")
    print(result_risk.json(indent=2))