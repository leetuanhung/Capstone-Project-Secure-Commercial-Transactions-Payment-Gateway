"""
Demo script for Fraud Detection System
Run from root directory: python backend/test_fraud_detection.py
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.services.payment_service.security.fraud_detection import (
    FraudDetector,
    TransactionInput
)

def print_result(title: str, result):
    """In kết quả với format đẹp"""
    print(f"\n{'='*60}")
    print(f"🧪 {title}")
    print(f"{'='*60}")
    print(f"{'✅ PASS' if not result.is_fraud else '🔴 BLOCKED'}")
    print(f"Fraud Score: {result.score:.2f} ({result.score*100:.1f}%)")
    print(f"Triggered Rules: {', '.join(result.triggered_rules) if result.triggered_rules else 'None'}")
    print(f"Message: {result.message}")
    print(f"{'='*60}")

def main():
    print("\n🛡️  FRAUD DETECTION SYSTEM - DEMO\n")
    
    # Khởi tạo detector
    detector = FraudDetector()
    
    # Test 1: Giao dịch bình thường
    tx1 = TransactionInput(
        user_id="user_123",
        amount=150.00,  # 150 USD
        currency="usd",
        ip_address="123.45.67.89",
        billing_country="VN"
    )
    result1 = detector.assess_transaction(tx1)
    print_result("Test 1: Giao dịch bình thường (VN, $150)", result1)
    
    # Test 2: Giao dịch giá trị rất cao
    tx2 = TransactionInput(
        user_id="user_456",
        amount=25000.00,  # 25,000 USD - Vượt ngưỡng 10,000
        currency="usd",
        ip_address="10.0.0.1",
        billing_country="US"
    )
    result2 = detector.assess_transaction(tx2)
    print_result("Test 2: Giao dịch giá trị cao (US, $25,000)", result2)
    
    # Test 3: Quốc gia rủi ro cao
    tx3 = TransactionInput(
        user_id="user_789",
        amount=50.00,  # Chỉ $50 nhưng từ quốc gia rủi ro cao
        currency="usd",
        ip_address="11.22.33.44",
        billing_country="KP"  # Triều Tiên
    )
    result3 = detector.assess_transaction(tx3)
    print_result("Test 3: Quốc gia rủi ro cao (KP, $50)", result3)
    
    # Test 4: Thiếu IP
    tx4 = TransactionInput(
        user_id="user_999",
        amount=100.00,
        currency="usd",
        ip_address=None,  # Không có IP
        billing_country="VN"
    )
    result4 = detector.assess_transaction(tx4)
    print_result("Test 4: Thiếu IP address (VN, $100)", result4)
    
    # Test 5: Giao dịch VND lớn
    tx5 = TransactionInput(
        user_id="user_555",
        amount=300000000.00 / 24000,  # ~12,500 USD (convert từ 300M VND)
        currency="vnd",
        ip_address="192.168.1.1",
        billing_country="VN"
    )
    result5 = detector.assess_transaction(tx5)
    print_result("Test 5: Giao dịch VND lớn (VN, 300M VND ~ $12,500)", result5)
    
    # Tổng kết
    print("\n" + "="*60)
    print("📊 SUMMARY")
    print("="*60)
    results = [result1, result2, result3, result4, result5]
    blocked = sum(1 for r in results if r.is_fraud)
    passed = len(results) - blocked
    print(f"Total Tests: {len(results)}")
    print(f"✅ Passed: {passed}")
    print(f"🔴 Blocked: {blocked}")
    print(f"Block Rate: {(blocked/len(results)*100):.1f}%")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
