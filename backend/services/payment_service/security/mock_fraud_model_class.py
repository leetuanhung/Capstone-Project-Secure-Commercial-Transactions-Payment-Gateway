
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
