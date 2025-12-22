#!/usr/bin/env python3
"""
Quick test script to verify all imports work correctly
Run this before deploying to catch import errors early
"""
import sys
import os

print("="*60)
print("🧪 Testing all critical imports...")
print("="*60)

# Test 1: Backend package
try:
    import backend
    print("✅ backend package")
except Exception as e:
    print(f"❌ backend package: {e}")
    sys.exit(1)

# Test 2: Config
try:
    from backend.config.config import settings
    print(f"✅ backend.config.config - Stripe key: {'set' if settings.Stripe_Secret_Key else 'missing'}")
except Exception as e:
    print(f"❌ backend.config.config: {e}")
    sys.exit(1)

# Test 3: Database
try:
    from backend.database.database import engine, get_db
    print("✅ backend.database.database")
except Exception as e:
    print(f"❌ backend.database.database: {e}")
    sys.exit(1)

# Test 4: Models
try:
    from backend.models.models import User
    print("✅ backend.models.models")
except Exception as e:
    print(f"❌ backend.models.models: {e}")
    sys.exit(1)

# Test 5: Services
try:
    from backend.services.payment_service import payment
    from backend.services.order_service import order
    from backend.services.user_service import user
    print("✅ All services")
except Exception as e:
    print(f"❌ Services: {e}")
    sys.exit(1)

# Test 6: Main app
try:
    from backend.main import app
    print(f"✅ backend.main - app type: {type(app).__name__}, routes: {len(app.routes)}")
except Exception as e:
    print(f"❌ backend.main: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("="*60)
print("✅ All imports successful!")
print("="*60)
