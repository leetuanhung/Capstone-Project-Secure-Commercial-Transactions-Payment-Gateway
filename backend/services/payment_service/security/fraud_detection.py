# security/fraud_detection.py

from pydantic import BaseModel, Field
from typing import List, Set, Optional
import datetime
import os
import joblib
import math

# DB access for history-based features
from backend.database.database import SessionLocal
from backend.models import models as db_models

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
        self.model_info = None

        # Nếu có đường dẫn model trong biến môi trường, thử load
        model_path = os.getenv("FRAUD_MODEL_PATH")
        if model_path:
            try:
                # Import class definition trước khi unpickle
                import sys
                from pathlib import Path
                model_dir = Path(model_path).parent
                if str(model_dir) not in sys.path:
                    sys.path.insert(0, str(model_dir))
                
                # Thử import class (nếu có)
                try:
                    from mock_fraud_model_class import MockFraudModel
                except ImportError:
                    pass  # Class có thể không cần thiết cho model thật
                
                self.model = joblib.load(model_path)
                self.model_info = {"path": model_path}
                print(f"Fraud Detector: loaded ML model from {model_path}")
            except Exception as e:
                print(f"⚠️ Could not load fraud model '{model_path}': {e}")

        print("Fraud Detector initialized.")

    def _get_ml_score(self, transaction: TransactionInput) -> float:
        """
        Hàm (riêng tư) để chấm điểm bằng mô hình ML.
        Đây là phần giữ chỗ (placeholder).
        """
        # Nếu không có model—trả điểm mặc định
        if not self.model:
            return 0.1

        # Nếu model tồn tại, build các features đơn giản từ lịch sử người dùng
        try:
            # Nỗ lực lấy lịch sử đơn hàng nếu user_id trông giống số (id user)
            user_orders = []
            try:
                uid = int(transaction.user_id)
                user_orders = self._get_user_order_history(uid, limit=100)
                print(f"📊 Found {len(user_orders)} orders for user_id={uid}")
                if user_orders:
                    for i, order in enumerate(user_orders[:5]):  # In 5 đơn gần nhất
                        print(f"   Order {i+1}: id={order.id}, price={order.total_price}, created={order.created_at}")
            except Exception as e:
                print(f"⚠️ Could not load order history: {e}")
                user_orders = []

            # Tính các feature cơ bản
            amounts = [o.total_price for o in user_orders if o.total_price is not None]
            # Always use offset-aware UTC datetime for comparison
            now = datetime.datetime.now(datetime.timezone.utc)

            def count_since(days: int):
                cutoff = now - datetime.timedelta(days=days)
                def to_aware(dt):
                    if dt is None:
                        return None
                    if dt.tzinfo is None:
                        # Assume naive datetimes are UTC
                        return dt.replace(tzinfo=datetime.timezone.utc)
                    return dt
                return sum(1 for o in user_orders if o.created_at and to_aware(o.created_at) >= cutoff)

            avg_amount = float(sum(amounts) / len(amounts)) if amounts else 0.0
            max_amount = float(max(amounts)) if amounts else 0.0
            std_amount = float(math.sqrt(sum((a - avg_amount) ** 2 for a in amounts) / len(amounts))) if len(amounts) > 1 else 0.0
            cnt_7d = count_since(7)
            cnt_30d = count_since(30)
            last_order_seconds = None
            if user_orders and user_orders[0].created_at:
                created_at = user_orders[0].created_at
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=datetime.timezone.utc)
                last_order_seconds = (now - created_at).total_seconds()
            last_order_seconds = float(last_order_seconds) if last_order_seconds is not None else 1e9

            # Chuẩn bị feature vector (sắp xếp theo cùng một thứ tự mà model training dùng)
            features = [
                float(transaction.amount),
                avg_amount,
                max_amount,
                std_amount,
                float(cnt_7d),
                float(cnt_30d),
                last_order_seconds,
            ]
            
            # Debug log
            print(f"🔍 ML Features for user {transaction.user_id}:")
            print(f"   - Current amount: {transaction.amount}")
            print(f"   - Avg amount: {avg_amount:.2f}")
            print(f"   - Max amount: {max_amount:.2f}")
            print(f"   - Count 7d: {cnt_7d}, Count 30d: {cnt_30d}")
            print(f"   - Last order seconds: {last_order_seconds:.0f}")

            # Chuyển thành dạng phù hợp cho model
            X = [features]

            # Dự đoán xác suất nếu model hỗ trợ
            if hasattr(self.model, "predict_proba"):
                prob = float(self.model.predict_proba(X)[0][1])
                print(f"🎯 ML Fraud Score: {prob:.2%}")
                return prob
            else:
                pred = self.model.predict(X)
                # Nếu dự đoán trả về lớp 0/1, map sang 0.5/0.99 để biểu diễn xác suất
                try:
                    val = float(pred[0])
                    return 0.99 if val == 1 else 0.01
                except Exception:
                    return 0.1

        except Exception as e:
            print(f"⚠️ ML scoring error: {e}")
            return 0.1

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

    def _get_user_order_history(self, user_id: int, limit: int = 100):
        """
        Trả về danh sách các Order (đã sắp xếp theo created_at DESC) để feature engineering.
        """
        session = SessionLocal()
        try:
            orders = (
                session.query(db_models.Order)
                .filter(db_models.Order.owner_id == user_id)
                .order_by(db_models.Order.created_at.desc())
                .limit(limit)
                .all()
            )
            return orders
        except Exception:
            return []
        finally:
            session.close()

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