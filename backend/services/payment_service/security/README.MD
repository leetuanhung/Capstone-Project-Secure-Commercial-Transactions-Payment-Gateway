# Payment Security Core Module

## 📋 Overview

Comprehensive security module for PCI-DSS compliant payment processing with advanced fraud detection, encryption, and 3D Secure authentication.

## 🏗️ Architecture

```
security/
├── __init__.py                 # Module initialization
├── tokenization.py             # 🔐 Card tokenization (PCI DSS)
├── hsm_client.py              # 🔒 AWS KMS/CloudHSM integration
├── fraud_detection.py         # 🤖 ML fraud scoring + rules
├── pci_auditor.py            # 📋 PCI-DSS compliance checks
├── three_d_secure.py         # 🛡️ 3D Secure flows (3DS2/SCA)
├── encryption.py             # 🔐 Field-level encryption
└── README.md                 # This file
```

## 🚀 Quick Start

### Installation

```bash
pip install cryptography boto3
```

### Basic Usage

```python
from security import (
    card_tokenizer,
    fraud_detector,
    three_d_secure,
    field_encryption
)

# 1. Tokenize card
token_result = card_tokenizer.generate_token(
    card_number="4532015112830366",
    cvv="123",
    expiry="12/25",
    cardholder_name="JOHN DOE"
)

# 2. Check fraud
fraud_result = fraud_detector.calculate_fraud_score({
    'amount': 250.00,
    'card_fingerprint': token_result['fingerprint'],
    'ip_address': '123.45.67.89'
})

# 3. Encrypt data
encrypted = field_encryption.encrypt_field("sensitive_data")
```

## 📦 Modules

### 1. Card Tokenization (`tokenization.py`)

**Purpose**: Convert sensitive card data into secure tokens (PCI-DSS Requirement 3.4)

**Features**:
- ✅ Luhn algorithm validation
- ✅ Secure token generation (cryptographically random)
- ✅ Card brand detection (Visa, Mastercard, Amex, Discover)
- ✅ PAN masking (show only last 4 digits)
- ✅ Card fingerprinting
- ✅ Token expiration (1 hour default)

**Usage**:
```python
from security import card_tokenizer

# Generate token
result = card_tokenizer.generate_token(
    card_number="4532015112830366",
    cvv="123",
    expiry="12/25",
    cardholder_name="JOHN DOE"
)

# Result:
# {
#     'token': 'tok_xxxxx',
#     'masked_card': '************0366',
#     'card_brand': 'Visa',
#     'fingerprint': 'abc123def456'
# }

# Detokenize (when needed for processing)
original = card_tokenizer.detokenize(result['token'])
```

### 2. HSM/KMS Integration (`hsm_client.py`)

**Purpose**: Hardware Security Module integration via AWS KMS

**Features**:
- ✅ Master key creation & management
- ✅ AES-256 encryption/decryption
- ✅ Data key generation (envelope encryption)
- ✅ Automatic key rotation
- ✅ Encryption context (AEAD)

**Usage**:
```python
from security import hsm_client

# Encrypt with KMS
ciphertext = hsm_client.encrypt_data(
    plaintext="4532015112830366",
    key_id="your-kms-key-id",
    context={'data_type': 'card_number'}
)

# Decrypt
plaintext = hsm_client.decrypt_data(
    ciphertext=ciphertext,
    key_id="your-kms-key-id",
    context={'data_type': 'card_number'}
)
```

### 3. Fraud Detection (`fraud_detection.py`)

**Purpose**: ML-based fraud scoring with real-time risk assessment

**Features**:
- ✅ Multi-factor risk scoring (0-100)
- ✅ Velocity checking (transaction frequency)
- ✅ Geographic anomaly detection
- ✅ Device fingerprinting
- ✅ Amount anomaly detection
- ✅ Blacklist management
- ✅ Risk level classification (SAFE, LOW, MEDIUM, HIGH, CRITICAL)

**Risk Factors**:
1. Transaction amount anomaly
2. High velocity (too many transactions)
3. Geographic impossible travel
4. Unusual transaction time
5. VPN/Proxy detection
6. New device usage
7. Blacklisted card

**Usage**:
```python
from security import fraud_detector

# Calculate fraud score
result = fraud_detector.calculate_fraud_score({
    'amount': 1500.00,
    'card_fingerprint': 'abc123',
    'location': {'country': 'US'},
    'ip_address': '123.45.67.89',
    'device_id': 'device_xyz'
})

# Result:
# {
#     'score': 45,
#     'risk_level': 'MEDIUM',
#     'factors': ['UNUSUAL_AMOUNT', 'NEW_DEVICE'],
#     'recommendation': 'MANUAL_REVIEW'
# }
```

### 4. PCI-DSS Auditor (`pci_auditor.py`)

**Purpose**: Automated PCI-DSS compliance checking

**Features**:
- ✅ All 12 PCI-DSS requirements coverage
- ✅ Automated audit trails
- ✅ Storage configuration validation
- ✅ Compliance scoring
- ✅ Detailed reporting

**Key Requirements Checked**:
- Requirement 3: Protect stored cardholder data
- Requirement 4: Encrypt transmission
- Requirement 7: Restrict access
- Requirement 8: Unique IDs & authentication
- Requirement 10: Track & monitor access

**Usage**:
```python
from security import pci_auditor

# Run full audit
audit_result = pci_auditor.run_full_audit()

# Check storage compliance
storage_check = pci_auditor.check_card_data_storage({
    'stores_full_pan': False,
    'stores_cvv': False,
    'encryption_enabled': True
})

# Get compliance report
report = pci_auditor.get_compliance_report()
```

### 5. 3D Secure (`three_d_secure.py`)

**Purpose**: 3DS 2.0/SCA implementation for PSD2 compliance

**Features**:
- ✅ 3DS 2.2.0 protocol support
- ✅ Risk-based authentication (RBA)
- ✅ Frictionless flow for low-risk transactions
- ✅ Multiple challenge types (OTP SMS, Email, Biometric)
- ✅ SCA exemptions (low-value, trusted beneficiary, TRA)
- ✅ CAVV generation
- ✅ Liability shift indication

**Flow Types**:
1. **Frictionless**: No challenge (low risk)
2. **Challenge**: OTP/Biometric verification (medium/high risk)

**Usage**:
```python
from security import three_d_secure

# Initiate authentication
auth_request = three_d_secure.initiate_authentication({
    'amount': 250.00,
    'merchant_id': 'MERCHANT_001',
    'email': 'customer@example.com',
    'transaction_id': 'TXN_123'
})

if auth_request['challenge_required']:
    # Send OTP
    three_d_secure.send_challenge_otp(
        auth_request['three_ds_session_id'],
        method='SMS'
    )
    
    # Verify response
    result = three_d_secure.verify_challenge(
        auth_request['three_ds_session_id'],
        challenge_response='123456'
    )
```

### 6. Field-Level Encryption (`encryption.py`)

**Purpose**: AES-256 encryption for sensitive data fields

**Features**:
- ✅ AES-256-GCM (authenticated encryption)
- ✅ Fernet encryption (AES-128 CBC + HMAC)
- ✅ Context-based encryption (AEAD)
- ✅ Key rotation support
- ✅ Data masking utilities
- ✅ Secure storage wrapper

**Usage**:
```python
from security import field_encryption, data_masking

# Encrypt single field
encrypted = field_encryption.encrypt_field(
    plaintext="4532015112830366",
    context={'data_type': 'card'}
)

# Decrypt
decrypted = field_encryption.decrypt_field(
    ciphertext=encrypted,
    context={'data_type': 'card'}
)

# Mask sensitive data
masked = data_masking.mask_card_number("4532015112830366")
# Output: "************0366"
```

## 🔐 Security Best Practices

### 1. **Never Store CVV/PIN**
```python
# ❌ WRONG
store_in_database(cvv="123")

# ✅ CORRECT
# Only use CVV for real-time authorization, then discard
process_payment(cvv="123")  # Use immediately
# CVV is never stored
```

### 2. **Always Tokenize Cards**
```python
# ❌ WRONG
store_in_database(card_number="4532015112830366")

# ✅ CORRECT
token = card_tokenizer.generate_token(...)
store_in_database(token=token['token'])
```

### 3. **Encrypt Stored Data**
```python
# ❌ WRONG
database.save(email="user@example.com")

# ✅ CORRECT
encrypted_email = field_encryption.encrypt_field("user@example.com")
database.save(encrypted_email=encrypted_email)
```

### 4. **Mask Data in Logs**
```python
# ❌ WRONG
logger.info(f"Processing card: {card_number}")

# ✅ CORRECT
masked = data_masking.mask_card_number(card_number)
logger.info(f"Processing card: {masked}")
```

## 🎯 Complete Payment Flow

```python
from security import (
    card_tokenizer,
    fraud_detector,
    three_d_secure,
    field_encryption,
    pci_auditor
)

def process_secure_payment(payment_data):
    # 1. Tokenize
    token = card_tokenizer.generate_token(...)
    
    # 2. Fraud check
    fraud_result = fraud_detector.calculate_fraud_score(...)
    if fraud_result['risk_level'] == 'CRITICAL':
        return {'error': 'Transaction blocked'}
    
    # 3. 3DS authentication
    if fraud_result['recommendation'] == 'REQUIRE_3DS_VERIFICATION':
        auth_result = three_d_secure.initiate_authentication(...)
        if auth_result['challenge_required']:
            # Handle challenge (OTP/Biometric)
            pass  # Implement challenge handling
```

## Chạy test cho phần `security`

Tóm tắt nhanh:
- Test dùng pytest (unit + async).  
- Đặt test vào thư mục `backend/services/security/tests/` (ví dụ: `tests/test_tokenization.py`, `tests/test_fraud_detection.py`, ...).  
- Một số test cần mock AWS (HSM/KMS) — dùng `moto` hoặc mocking thủ công.

1) Cài dev dependencies (local):
- Tạo virtualenv rồi cài:
  - Windows:
    - python -m venv .venv
    - .venv\Scripts\activate
  - Unix/macOS:
    - python -m venv .venv
    - source .venv/bin/activate
- Cài pytest và công cụ hữu ích:
  - pip install -U pytest pytest-asyncio httpx moto coverage

2) Cấu trúc test (gợi ý)
- backend/services/security/tests/
  - test_tokenization.py
  - test_fraud_detection.py
  - test_encryption.py
  - test_three_d_secure.py
  - test_pci_auditor.py
  - test_hsm_client.py  (nếu dùng moto để mock KMS)

3) Ví dụ lệnh chạy:
- Chạy toàn bộ tests:
  - pytest -q
- Chạy tests trong thư mục security:
  - pytest backend/services/security/tests -q
- Chạy một file cụ thể:
  - pytest backend/services/security/tests/test_tokenization.py -q
- Chạy 1 test cụ thể:
  - pytest backend/services/security/tests/test_tokenization.py::test_generate_token -q
- Chạy kèm coverage:
  - coverage run -m pytest && coverage report -m

4) Gợi ý viết test nhanh (ví dụ nội dung file):
- test_tokenization.py (ví dụ)
  - Kiểm tra Luhn validation, generate_token trả mask + token, detokenize hoạt động.
- test_fraud_detection.py
  - Tạo TransactionInput với amount cao/low để assert risk levels và triggered rules.
- test_encryption.py
  - Encrypt/decrypt với FieldEncryption và AESEncryption (sử dụng master key từ env mock).
- test_hsm_client.py
  - Nếu dùng moto để mock KMS, mark test với moto.mock_kms.

5) Test chạy trong Docker (tùy chọn)
- Nếu dự án chạy trong container, build image dev hoặc chạy pytest trong container mount source:
  - docker run --rm -v %cd%:/app -w /app python:3.11-slim bash -c "pip install pytest moto && pytest backend/services/security/tests -q"

6) Lưu ý bảo mật khi test
- Không commit secret thật (.env chứa Key_AES/Stripe keys). Dùng biến môi trường test hoặc file .env.test.
- Không log PAN/CVV trong test output.

7) CI (GitHub Actions) - ví dụ job đơn giản
- steps:
  - Checkout
  - Set up Python
  - Install deps
  - Run pytest backend/services/security/tests -q
  - (Optional) upload coverage

Kết thúc — bạn có thể thêm ví dụ test files theo mẫu trên vào `backend/services/security/tests/` rồi chạy các lệnh pytest nêu ở trên.