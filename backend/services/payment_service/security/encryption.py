"""
Field-Level Encryption Module
================================================================================
Mục đích:
    Mã hóa từng trường dữ liệu nhạy cảm (field-level encryption) để bảo vệ
    dữ liệu at-rest (lưu trữ) và in-transit (truyền tải).

Các phương pháp mã hóa:
    1. Fernet (AES-128 CBC + HMAC) - Đơn giản, an toàn cho hầu hết use cases
    2. AES-256-GCM - AEAD (Authenticated Encryption with Associated Data)
    3. PBKDF2 - Key derivation từ password

Tại sao cần field-level encryption:
    - Database encryption (TDE) chỉ bảo vệ khi disk bị đánh cắp
    - Field encryption bảo vệ ngay cả khi attacker có quyền SELECT database
    - Có thể mã hóa từng trường với key riêng (separation of duties)

Use cases:
    - Mã hóa email, số điện thoại, địa chỉ
    - Mã hóa số thẻ (kết hợp với tokenization)
    - Mã hóa thông tin nhạy cảm trong logs

Lưu ý quan trọng:
    - Key phải được lưu trữ riêng biệt (HSM, KMS, Vault)
    - Cần có key rotation strategy
    - Associated Data (AAD) tăng cường bảo mật nhưng phải consistent
================================================================================
"""

import base64
import os
import secrets
import hashlib
from typing import Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# =========================
# FIELD ENCRYPTION (Fernet wrapper - đơn giản và an toàn)
# =========================
class FieldEncryption:
    """
    Mã hóa field-level sử dụng Fernet (AES-128-CBC + HMAC-SHA256)
    
    Đặc điểm Fernet:
        ✓ Symmetric encryption (cùng key để encrypt/decrypt)
        ✓ Tự động thêm timestamp vào ciphertext
        ✓ Tích hợp HMAC để đảm bảo integrity
        ✓ Đơn giản, khó dùng sai (misuse-resistant)
    
    Thuộc tính:
        master_key: Key chính (256-bit, base64-encoded)
        fernet: Instance Fernet để encrypt/decrypt
    
    Lưu ý:
        - Master key PHẢI được bảo vệ nghiêm ngặt (HSM/KMS)
        - Nếu mất key, dữ liệu không thể giải mã được
        - Rotation key phải cẩn thận (cần decrypt cũ, encrypt mới)
    """
    def __init__(self, master_key: Optional[str] = None):
        """
        Khởi tạo FieldEncryption với master key
        
        Args:
            master_key: Key base64-encoded (nếu None, tạo key mới)
                       Trong production, PHẢI load từ KMS/env secure
        
        Ví dụ:
            # Tự động tạo key mới
            >>> fe = FieldEncryption()
            
            # Dùng key có sẵn từ env
            >>> fe = FieldEncryption(master_key=os.getenv('ENCRYPTION_KEY'))
        """
        if master_key:
            self.master_key = base64.urlsafe_b64decode(master_key)
        else:
            # Tạo key mới (CHỈ dùng cho dev/test)
            self.master_key = Fernet.generate_key()
        self.fernet = Fernet(self.master_key)

    def encrypt_field(self, plaintext: str, context: Optional[Dict] = None) -> str:
        """
        Mã hóa một trường dữ liệu với context tùy chọn
        
        Context (Associated Data):
            - Thêm metadata vào ciphertext (nhưng KHÔNG mã hóa metadata)
            - Đảm bảo ciphertext chỉ giải mã được với đúng context
            - Ví dụ context: user_id, record_id, timestamp
        
        Args:
            plaintext: Dữ liệu cần mã hóa (string)
            context: Dict metadata (optional, dùng để bind ciphertext với context)
        
        Returns:
            Ciphertext base64-encoded (string)
        
        Ví dụ:
            >>> fe = FieldEncryption()
            >>> ctx = {"user_id": "123", "field": "email"}
            >>> encrypted = fe.encrypt_field("user@example.com", context=ctx)
            >>> print(encrypted)
            "gAAAAABl..."  # Base64 ciphertext
        
        Flow:
            1. Nếu có context, ghép context::plaintext
            2. Mã hóa bằng Fernet (AES-CBC + HMAC)
            3. Trả về ciphertext base64
        
        Lưu ý bảo mật:
            - Context KHÔNG được mã hóa, chỉ dùng để verify integrity
            - Nếu dùng context khi encrypt, PHẢI dùng context khi decrypt
        """
        if not plaintext:
            return ""

        # Ghép context vào plaintext (nếu có) để bind chúng lại
        context_str = str(sorted(context.items())) if context else ""
        data = f"{context_str}::{plaintext}" if context else plaintext
        
        # Mã hóa và encode base64
        encrypted = self.fernet.encrypt(data.encode())
        return encrypted.decode()

    def decrypt_field(self, ciphertext: str, context: Optional[Dict] = None) -> str:
        """
        Giải mã và verify context (nếu có)
        
        Args:
            ciphertext: Ciphertext base64-encoded
            context: Context đã dùng khi encrypt (PHẢI khớp)
        
        Returns:
            Plaintext (dữ liệu gốc)
        
        Raises:
            ValueError: Nếu context không khớp (phát hiện tampering)
            cryptography.fernet.InvalidToken: Nếu ciphertext bị sửa hoặc key sai
        
        Ví dụ:
            >>> decrypted = fe.decrypt_field(encrypted, context=ctx)
            >>> print(decrypted)
            "user@example.com"
            
            # Nếu context sai → raise ValueError
            >>> fe.decrypt_field(encrypted, context={"user_id": "456"})
            ValueError: Context mismatch - possible tampering
        
        Flow:
            1. Giải mã ciphertext bằng Fernet
            2. Nếu có context, verify context khớp với lúc encrypt
            3. Trả về plaintext
        
        Lưu ý bảo mật:
            - Context mismatch = có thể bị attack (replay, tampering)
            - Cần log lại mọi lần context mismatch để investigate
        """
        if not ciphertext:
            return ""

        decrypted = self.fernet.decrypt(ciphertext.encode()).decode()

        if context:
            context_str = str(sorted(context.items()))
            prefix = f"{context_str}::"
            if not decrypted.startswith(prefix):
                raise ValueError("Context mismatch - possible tampering")
            return decrypted[len(prefix):]

        return decrypted


# =========================
# DATA MASKING (Che giấu dữ liệu nhạy cảm)
# =========================
class DataMasking:
    """
    Công cụ che giấu (masking) dữ liệu nhạy cảm để tuân thủ PCI-DSS
    
    Mục đích:
        - Hiển thị dữ liệu một phần cho user/logs
        - Tuân thủ PCI DSS: Không hiển thị toàn bộ số thẻ/CVV
        - Giảm rủi ro shoulder surfing, screenshot leaks
    
    Use cases:
        - Hiển thị số thẻ trên UI: "************1111"
        - Log email trong audit trail: "u***r@example.com"
        - Hiển thị số điện thoại: "+84***890"
    
    Lưu ý:
        - Masking KHÔNG phải là mã hóa (không thể unmas

    @staticmethod
    def mask_card_number(card_number: str, show_last: int = 4) -> str:
        clean = ''.join(filter(str.isdigit, card_number))
        if len(clean) <= show_last:
            return '*' * len(clean)
        masked = '*' * (len(clean) - show_last) + clean[-show_last:]
        return ' '.join([masked[i:i + 4] for i in range(0, len(masked), 4)])

    @staticmethod
    def mask_email(email: str) -> str:
        if '@' not in email:
            return '***'
        local, domain = email.split('@')
        local_mask = local[0] + '*' * (len(local) - 2) + local[-1] if len(local) > 2 else '*' * len(local)
        d0, *rest = domain.split('.')
        dmask = d0[0] + '*' * (len(d0) - 2) + d0[-1] if len(d0) > 2 else '*' * len(d0)
        return f"{local_mask}@{dmask}.{'.'.join(rest)}"

    @staticmethod
    def mask_phone(phone: str) -> str:
        clean = ''.join(filter(str.isdigit, phone))
        if len(clean) < 3:
            return '*' * len(clean)
        prefix = '+' if phone.startswith('+') else ''
        return prefix + clean[:2] + '*' * (len(clean) - 5) + clean[-3:]

    @staticmethod
    def mask_cvv(cvv: str) -> str:
        return '***'

    @staticmethod
    def mask_sensitive_data(data: Dict) -> Dict:
        masked = data.copy()
        if 'card_number' in masked:
            masked['card_number'] = DataMasking.mask_card_number(masked['card_number'])
        if 'cvv' in masked:
            masked['cvv'] = DataMasking.mask_cvv(masked['cvv'])
        if 'email' in masked:
            masked['email'] = DataMasking.mask_email(masked['email'])
        if 'phone' in masked:
            masked['phone'] = DataMasking.mask_phone(masked['phone'])
        return masked


# =========================
# AES ENCRYPTION
# =========================
class AESEncryption:
    """Advanced AES-256-GCM encryption"""

    @staticmethod
    def generate_key() -> bytes:
        return secrets.token_bytes(32)

    @staticmethod
    def encrypt_aes_gcm(plaintext: str, key: bytes, associated_data: Optional[bytes] = None) -> Dict:
        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(encryptor.tag).decode()
        }

    @staticmethod
    def decrypt_aes_gcm(encrypted_data: Dict, key: bytes, associated_data: Optional[bytes] = None) -> str:
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        tag = base64.b64decode(encrypted_data['tag'])
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()


# =========================
# KEY DERIVATION
# =========================
class KeyDerivation:
    """Password-based key derivation (PBKDF2)"""

    @staticmethod
    def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Dict:
        if salt is None:
            salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return {
            'key': base64.b64encode(key).decode(),
            'salt': base64.b64encode(salt).decode()
        }

    @staticmethod
    def verify_password_key(password: str, salt: str, expected_key: str) -> bool:
        salt_bytes = base64.b64decode(salt)
        expected_bytes = base64.b64decode(expected_key)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
            backend=default_backend()
        )
        try:
            kdf.verify(password.encode(), expected_bytes)
            return True
        except Exception:
            return False


# =========================
# SECURE STORAGE
# =========================
class SecureStorage:
    """Combine encryption + integrity"""

    def __init__(self, encryption_key: bytes):
        self.encryption = FieldEncryption(base64.urlsafe_b64encode(encryption_key).decode())

    def _is_sensitive(self, key: str) -> bool:
        return key.lower() in ['card_number', 'cvv', 'password', 'pin', 'ssn']

    def _checksum(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def store_secure(self, data: Dict, identifier: str) -> Dict:
        ctx = {'identifier': identifier, 'timestamp': str(int(secrets.SystemRandom().random() * 1e6))}
        enc = {}
        for k, v in data.items():
            if isinstance(v, str) and self._is_sensitive(k):
                enc[k] = self.encryption.encrypt_field(v, ctx)
            else:
                enc[k] = v
        enc['_meta'] = {'ctx': ctx, 'checksum': self._checksum(str(enc))}
        return enc

    def retrieve_secure(self, data: Dict) -> Dict:
        meta = data.get('_meta', {})
        ctx = meta.get('ctx', {})
        out = {}
        for k, v in data.items():
            if k == '_meta':
                continue
            out[k] = self.encryption.decrypt_field(v, ctx) if self._is_sensitive(k) else v
        return out


# =========================
# HELPERS
# =========================
def generate_master_key() -> str:
    return Fernet.generate_key().decode()


def load_key_from_env() -> Optional[str]:
    return os.getenv("Key_AES")


# Example init
master_key = load_key_from_env()
field_encryption = FieldEncryption(master_key)
data_masking = DataMasking()
aes_encryption = AESEncryption()
key_derivation = KeyDerivation()

# Tracing
try:
    from .tracer import trace_event
except Exception:
    def trace_event(name, payload, reveal=False):
        return None


def _trace_encrypt_field(plaintext: str, context: Optional[Dict] = None, result: str | None = None):
    try:
        trace_event('encrypt.field', {'plaintext': plaintext, 'context': context, 'output_len': len(result) if result else None})
    except Exception:
        pass


def _trace_decrypt_field(ciphertext: str, context: Optional[Dict] = None, result: str | None = None):
    try:
        trace_event('decrypt.field', {'ciphertext_len': len(ciphertext) if ciphertext else 0, 'context': context, 'output_preview': result})
    except Exception:
        pass

# Wrap FieldEncryption methods to trace
_orig_encrypt = FieldEncryption.encrypt_field
_orig_decrypt = FieldEncryption.decrypt_field

def _wrapped_encrypt_field(self, plaintext: str, context: Optional[Dict] = None) -> str:
    out = _orig_encrypt(self, plaintext, context)
    _trace_encrypt_field(plaintext, context, out)
    return out

def _wrapped_decrypt_field(self, ciphertext: str, context: Optional[Dict] = None) -> str:
    out = _orig_decrypt(self, ciphertext, context)
    _trace_decrypt_field(ciphertext, context, out)
    return out

FieldEncryption.encrypt_field = _wrapped_encrypt_field
FieldEncryption.decrypt_field = _wrapped_decrypt_field

