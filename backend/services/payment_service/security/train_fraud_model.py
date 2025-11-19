"""
Script tạo mock ML model để test fraud detection
Model này sẽ phát hiện:
- Giao dịch có số tiền bất thường (quá cao so với lịch sử)
- Giao dịch liên tục trong thời gian ngắn
- Giao dịch đầu tiên có giá trị cao

QUAN TRỌNG: Lưu class definition vào file riêng để pickle có thể import
"""

import joblib
import numpy as np
from pathlib import Path
import sys

# Tạo file chứa class definition
model_class_code = '''
import numpy as np

class MockFraudModel:
    """
    Mock model đơn giản để test fraud detection
    Dự đoán dựa trên các quy tắc logic thay vì ML thật
    """
    
    def predict_proba(self, X):
        """
        X là array với 7 features:
        [transaction_amount, avg_amount, max_amount, std_amount, 
         cnt_7d, cnt_30d, last_order_seconds]
        
        Trả về [[prob_normal, prob_fraud]]
        """
        results = []
        for features in X:
            amount = features[0]
            avg_amount = features[1]
            max_amount = features[2]
            std_amount = features[3]
            cnt_7d = features[4]
            cnt_30d = features[5]
            last_order_seconds = features[6]
            
            fraud_score = 0.0
            
            # Rule 1: Giao dịch đầu tiên có giá trị cao
            # ĐIỀU CHỈNH: Thay đổi 2000 thành số tiền bạn muốn (đơn vị: VND trong DB sau khi chia 100)
            if cnt_30d == 0 and amount > 200000:  # > 200,000 VND trên UI
                fraud_score += 0.6
                print(f"🚨 ML Rule 1: First transaction with high amount ({amount})")
            
            # Rule 2: Số tiền cao hơn gấp 3 lần trung bình lịch sử
            if avg_amount > 0 and amount > avg_amount * 3:
                fraud_score += 0.4
                print(f"🚨 ML Rule 2: Amount {amount} >> 3x avg {avg_amount}")
            
            # Rule 3: Giao dịch liên tiếp trong < 1 phút (60 seconds)
            if last_order_seconds < 60:
                fraud_score += 0.3
                print(f"🚨 ML Rule 3: Rapid transaction ({last_order_seconds}s since last)")
            
            # Rule 4: Quá nhiều giao dịch trong 7 ngày (> 10)
            if cnt_7d > 10:
                fraud_score += 0.2
                print(f"🚨 ML Rule 4: Too many transactions in 7 days ({cnt_7d})")
            
            # Rule 5: Số tiền quá cao
            # ĐIỀU CHỈNH: Thay đổi 5000 thành số tiền bạn muốn
            if amount > 5000:  # > 500,000 VND trên UI
                fraud_score += 0.5
                print(f"🚨 ML Rule 5: Very high amount ({amount})")
            
            # Normalize score to [0, 1]
            fraud_score = min(fraud_score, 1.0)
            normal_score = 1.0 - fraud_score
            
            results.append([normal_score, fraud_score])
        
        return np.array(results)
    
    def predict(self, X):
        """Predict class (0 = normal, 1 = fraud)"""
        probas = self.predict_proba(X)
        return (probas[:, 1] > 0.5).astype(int)
'''

if __name__ == "__main__":
    # Lưu class definition vào file
    class_file = Path(__file__).parent / "mock_fraud_model_class.py"
    with open(class_file, 'w', encoding='utf-8') as f:
        f.write(model_class_code)
    
    print(f"✅ Created model class file: {class_file}")
    
    # Import class từ file vừa tạo
    sys.path.insert(0, str(Path(__file__).parent))
    from mock_fraud_model_class import MockFraudModel
    
    # Tạo và lưu model
    model = MockFraudModel()
    
    # Lưu model vào file
    model_path = Path(__file__).parent / "fraud_model_mock.pkl"
    joblib.dump(model, model_path)
    
    print(f"✅ Mock ML model saved to: {model_path}")
    print("\nĐể sử dụng model này, thêm vào file .env:")
    print(f"FRAUD_MODEL_PATH={model_path}")
    
    # Test model
    print("\n" + "="*60)
    print("TEST SCENARIOS:")
    print("="*60)
    
    # Scenario 1: Giao dịch bình thường
    print("\n1. NORMAL TRANSACTION (user đã có 5 đơn, avg=500):")
    X_normal = [[600, 500, 800, 100, 5, 10, 86400]]  # 1 ngày trước
    result = model.predict_proba(X_normal)
    print(f"   Fraud probability: {result[0][1]:.2%}")
    
    # Scenario 2: Giao dịch đầu tiên với số tiền cao
    print("\n2. FRAUD: First transaction with high amount:")
    X_fraud1 = [[3000, 0, 0, 0, 0, 0, 1e9]]
    result = model.predict_proba(X_fraud1)
    print(f"   Fraud probability: {result[0][1]:.2%}")
    
    # Scenario 3: Giao dịch cao gấp 5 lần trung bình
    print("\n3. FRAUD: Amount 5x higher than average:")
    X_fraud2 = [[5000, 1000, 2000, 300, 3, 8, 3600]]
    result = model.predict_proba(X_fraud2)
    print(f"   Fraud probability: {result[0][1]:.2%}")
    
    # Scenario 4: Giao dịch liên tiếp trong 30 giây
    print("\n4. FRAUD: Rapid consecutive transactions:")
    X_fraud3 = [[800, 500, 800, 100, 3, 5, 30]]
    result = model.predict_proba(X_fraud3)
    print(f"   Fraud probability: {result[0][1]:.2%}")
    
    # Scenario 5: Quá nhiều giao dịch + số tiền cao
    print("\n5. FRAUD: Too many transactions + high amount:")
    X_fraud4 = [[6000, 500, 1000, 200, 15, 20, 120]]
    result = model.predict_proba(X_fraud4)
    print(f"   Fraud probability: {result[0][1]:.2%}")
    
    print("\n" + "="*60)
    print("Ngưỡng fraud detection: 0.75 (75%)")
    print("Nếu fraud_score >= 0.75 → Transaction bị BLOCK")
    print("="*60)
    

