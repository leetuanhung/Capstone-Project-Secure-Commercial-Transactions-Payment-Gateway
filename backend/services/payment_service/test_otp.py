"""
Test script cho OTP Service
"""
import sys
from pathlib import Path

# Add backend to path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv(ROOT / ".env")

from backend.services.payment_service.otp_service import init_otp_service

def test_otp_basic():
    """Test gửi OTP cơ bản"""
    print("=" * 50)
    print("TEST 1: Basic OTP Send")
    print("=" * 50)
    
    otp_service = init_otp_service()
    
    if not otp_service:
        print("❌ OTP Service initialization failed")
        return False
    
    # THAY ĐỔI EMAIL NÀY THÀNH EMAIL CỦA BẠN
    test_email = "your-test-email@gmail.com"
    
    print(f"\n📧 Sending OTP to: {test_email}")
    otp = otp_service.send_otp(
        email=test_email,
        amount=100000,
        currency="vnd",
        order_id="TEST-001"
    )
    
    if otp:
        print(f"✅ OTP sent successfully!")
        print(f"   OTP Code: {otp}")
        print(f"\n🔍 Please check your email: {test_email}")
        print(f"   Subject: 🔒 Mã xác thực thanh toán - TEST-001")
        return True
    else:
        print("❌ Failed to send OTP")
        print("   Possible reasons:")
        print("   - GMAIL_USER or GMAIL_APP_PASSWORD not configured in .env")
        print("   - Invalid App Password")
        print("   - Network/firewall issue")
        return False


def test_otp_verify():
    """Test verify OTP"""
    print("\n" + "=" * 50)
    print("TEST 2: OTP Verification")
    print("=" * 50)
    
    otp_service = init_otp_service()
    
    # THAY ĐỔI EMAIL NÀY
    test_email = "your-test-email@gmail.com"
    order_id = "TEST-002"
    
    # Send OTP
    print(f"\n📧 Sending OTP to: {test_email}")
    otp = otp_service.send_otp(
        email=test_email,
        amount=50000,
        currency="vnd",
        order_id=order_id
    )
    
    if not otp:
        print("❌ Failed to send OTP")
        return False
    
    print(f"✅ OTP sent: {otp}")
    
    # Test correct OTP
    print(f"\n🔍 Testing correct OTP...")
    result = otp_service.verify_otp(test_email, order_id, otp)
    if result:
        print("✅ Correct OTP verified successfully")
    else:
        print("❌ Verification failed (should have passed)")
        return False
    
    # Test wrong OTP
    print(f"\n🔍 Testing wrong OTP...")
    result = otp_service.verify_otp(test_email, order_id, "999999")
    if not result:
        print("✅ Wrong OTP correctly rejected")
    else:
        print("❌ Wrong OTP was accepted (security issue!)")
        return False
    
    # Test reuse OTP
    print(f"\n🔍 Testing OTP reuse (should fail)...")
    result = otp_service.verify_otp(test_email, order_id, otp)
    if not result:
        print("✅ OTP reuse correctly prevented")
    else:
        print("❌ OTP was reused (security issue!)")
        return False
    
    return True


def test_otp_redis():
    """Test Redis storage"""
    print("\n" + "=" * 50)
    print("TEST 3: Redis Integration")
    print("=" * 50)
    
    try:
        from backend.middleware.rate_limiter import redis_client, USE_REDIS
        
        if not USE_REDIS:
            print("⚠️ Redis not available, using memory storage")
            return True
        
        otp_service = init_otp_service(redis_client)
        
        test_email = "redis-test@example.com"
        order_id = "TEST-REDIS"
        
        print(f"\n📧 Sending OTP...")
        otp = otp_service.send_otp(
            email=test_email,
            amount=75000,
            currency="vnd",
            order_id=order_id
        )
        
        if not otp:
            print("❌ Failed to send OTP")
            return False
        
        # Check Redis
        key = f"otp:{test_email}:{order_id}"
        stored_otp = redis_client.get(key)
        
        if stored_otp == otp:
            print(f"✅ OTP stored in Redis: {key}")
            
            # Check TTL
            ttl = redis_client.ttl(key)
            print(f"✅ TTL: {ttl} seconds (~{ttl//60} minutes)")
            
            # Cleanup
            redis_client.delete(key)
            print(f"✅ Cleanup successful")
            
            return True
        else:
            print(f"❌ OTP not found in Redis")
            return False
            
    except Exception as e:
        print(f"❌ Redis test failed: {e}")
        return False


if __name__ == "__main__":
    print("🧪 OTP Service Test Suite")
    print("=" * 50)
    
    import os
    gmail_user = os.getenv("GMAIL_USER")
    gmail_pass = os.getenv("GMAIL_APP_PASSWORD")
    
    if not gmail_user or not gmail_pass:
        print("❌ ERROR: Gmail credentials not configured!")
        print("\n📝 Please set in .env:")
        print("   GMAIL_USER=your-email@gmail.com")
        print("   GMAIL_APP_PASSWORD=your-app-password")
        print("\n📖 See SETUP_OTP.md for detailed instructions")
        sys.exit(1)
    
    print(f"📧 Gmail User: {gmail_user}")
    print(f"🔑 App Password: {gmail_pass[:4]}{'*' * (len(gmail_pass)-4)}")
    print()
    
    # Run tests
    results = []
    
    results.append(("Basic OTP Send", test_otp_basic()))
    results.append(("OTP Verification", test_otp_verify()))
    results.append(("Redis Integration", test_otp_redis()))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {name}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    
    print(f"\n🏆 Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ All tests passed!")
    else:
        print("⚠️ Some tests failed. Check logs above.")
