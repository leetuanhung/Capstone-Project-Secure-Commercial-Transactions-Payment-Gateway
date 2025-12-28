"""
Train fraud detection model thật bằng scikit-learn
- Dùng 7 features giống đồ án hiện tại:
  [transaction_amount, avg_amount, max_amount, std_amount, cnt_7d, cnt_30d, last_order_seconds]
- Tạo dataset synthetic có kiểm soát (dễ giải thích trong report)
- Train RandomForestClassifier
- Lưu model ra joblib .pkl để backend load qua FRAUD_MODEL_PATH
"""

from __future__ import annotations
import numpy as np
import joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score

RANDOM_SEED = 42

def make_synthetic_dataset(n: int = 60000, seed: int = RANDOM_SEED):
    """
    Tạo dataset giả lập nhưng "hợp lý" với fraud:
    - Fraud có xu hướng: amount bất thường cao so với lịch sử, giao dịch dồn dập, first-transaction lớn, velocity cao.
    - Normal: bám quanh lịch sử, tốc độ bình thường.
    """
    rng = np.random.default_rng(seed)

    # History features
    cnt_30d = rng.integers(0, 60, size=n)         # số giao dịch 30 ngày
    cnt_7d  = np.clip(cnt_30d // 4 + rng.integers(0, 4, size=n), 0, 30)

    avg_amount = rng.lognormal(mean=6.0, sigma=0.6, size=n)  # ~ vài trăm -> vài nghìn (tùy đơn vị)
    std_amount = avg_amount * rng.uniform(0.05, 0.6, size=n)
    max_amount = avg_amount * rng.uniform(1.0, 3.0, size=n)

    # last_order_seconds: normal thường lớn, fraud thường nhỏ
    last_order_seconds = rng.lognormal(mean=10.5, sigma=1.0, size=n)  # ~ vài phút -> nhiều giờ
    last_order_seconds = np.clip(last_order_seconds, 1, 1e9)

    # current amount
    amount = avg_amount * rng.uniform(0.6, 1.6, size=n)

    # Chèn tình huống "first transaction"
    first_mask = (cnt_30d == 0)
    amount[first_mask] = rng.lognormal(mean=6.5, sigma=0.8, size=first_mask.sum())
    max_amount[first_mask] = 0.0
    std_amount[first_mask] = 0.0
    avg_amount[first_mask] = 0.0

    # ----- Labeling rule để tạo ground-truth cho synthetic (giải thích được trong report) -----
    # Tạo "fraud score" từ nhiều tín hiệu (không phải mock predict nữa, đây chỉ dùng để sinh label dataset)
    score = np.zeros(n, dtype=float)

    # 1) First transaction high
    score += (first_mask & (amount > 2000)).astype(float) * 0.6

    # 2) Amount >> avg
    score += ((avg_amount > 0) & (amount > avg_amount * 3)).astype(float) * 0.4

    # 3) Rapid transaction
    score += (last_order_seconds < 60).astype(float) * 0.3

    # 4) Too many transactions
    score += (cnt_7d > 10).astype(float) * 0.2

    # 5) Very high amount absolute
    score += (amount > 5000).astype(float) * 0.5

    score = np.clip(score, 0.0, 1.0)

    # Convert score -> label, đồng thời thêm noise để mô phỏng thực tế
    y = (score >= 0.75).astype(int)

    # Noise nhẹ: 2% flip ngẫu nhiên
    noise = rng.random(n) < 0.02
    y[noise] = 1 - y[noise]

    X = np.column_stack([
        amount.astype(float),
        avg_amount.astype(float),
        max_amount.astype(float),
        std_amount.astype(float),
        cnt_7d.astype(float),
        cnt_30d.astype(float),
        last_order_seconds.astype(float),
    ])

    return X, y


def main():
    X, y = make_synthetic_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=10,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    # Evaluate
    prob = model.predict_proba(X_test)[:, 1]
    pred = (prob >= 0.5).astype(int)

    print("=== Evaluation ===")
    print("ROC-AUC:", roc_auc_score(y_test, prob))
    print(classification_report(y_test, pred, digits=4))

    # Save
    out_path = Path(__file__).parent / "fraud_model_rf.pkl"
    joblib.dump(model, out_path)
    print("\n✅ Saved model to:", out_path)
    print("\nAdd to .env:")
    print(f"FRAUD_MODEL_PATH={out_path}")

if __name__ == "__main__":
    main()