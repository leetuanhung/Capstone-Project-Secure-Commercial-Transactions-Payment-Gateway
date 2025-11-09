"""
Field-Level Encryption Module
================================================================================
Mục đích:
    Mã hóa từng trường dữ liệu nhạy cảm (field-level encryption) để bảo vệ
    dữ liệu at-rest (lưu trữ) và in-transit (truyền tải).

Các phương pháp mã hóa:
    1. AES-256-GCM - AEAD (Authenticated Encryption with Associated Data) - MAIN
    2. AES-256-GCM - Class AESEncryption (standalone utility)
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
import json
from typing import Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# =========================
# FIELD ENCRYPTION (AES-256-GCM - AEAD with native AAD)
# =========================
class FieldEncryption:
    """
    Mã hóa field-level sử dụng AES-256-GCM (AEAD)
    
    Đặc điểm AES-GCM:
        ✓ Authenticated Encryption with Associated Data (AEAD)
        ✓ Native AAD support (không cần ghép thủ công vào plaintext)
        ✓ Authentication tag tích hợp (16 bytes)
        ✓ Nhanh hơn CBC + HMAC (1 operation thay vì 2)
        ✓ Key size: 256-bit (mạnh hơn Fernet 128-bit)
    
    Thuộc tính:
        master_key: Key chính (256-bit = 32 bytes)
    
    Lưu ý:
        - Master key PHẢI được bảo vệ nghiêm ngặt (HSM/KMS)
        - KHÔNG BAO GIỜ reuse nonce với cùng key
        - Nếu mất key, dữ liệu không thể giải mã được
        - AAD phải consistent giữa encrypt và decrypt
    """
    def __init__(self, master_key: Optional[str] = None):
            """
            Nhận AES-256 key (32 bytes) ở dạng base64 hoặc tự động tạo.
            
            Args:
                master_key: Base64-encoded 32 bytes key hoặc None để tạo mới
            """
            if master_key is None:
                # Tạo key 256-bit mới
                self.master_key = secrets.token_bytes(32)
            else:
                # Decode base64 để lấy raw bytes
                try:
                    if isinstance(master_key, str):
                        self.master_key = base64.b64decode(master_key)
                    else:
                        self.master_key = master_key
                except Exception as e:
                    raise ValueError("Invalid key: must be base64-encoded 32 bytes") from e
            
            # Verify key length (phải đúng 32 bytes cho AES-256)
            if len(self.master_key) != 32:
                raise ValueError(f"AES-256 requires 32-byte key, got {len(self.master_key)} bytes")

    def encrypt_field(self, plaintext: str, context: Optional[Dict] = None) -> str:
        """
        Mã hóa một trường dữ liệu với AAD (Associated Authenticated Data)
        
        AAD (Associated Data):
            - Metadata được authenticate nhưng KHÔNG mã hóa
            - GCM native AAD: không ghép vào plaintext, xử lý riêng
            - Đảm bảo ciphertext chỉ giải mã được với đúng context
            - Ví dụ AAD: user_id, record_id, field_name
        
        Args:
            plaintext: Dữ liệu cần mã hóa (string)
            context: Dict metadata (optional, dùng làm AAD)
        
        Returns:
            JSON string chứa: {"ciphertext": "...", "nonce": "...", "tag": "...", "aad": "..."}
        
        Ví dụ:
            >>> fe = FieldEncryption()
            >>> ctx = {"user_id": "123", "field": "email"}
            >>> encrypted = fe.encrypt_field("user@example.com", context=ctx)
            >>> print(encrypted)
            '{"ciphertext": "Ax3k...", "nonce": "bH7q...", "tag": "9Km...", "aad": "..."}'
        
        Flow:
            1. Tạo nonce ngẫu nhiên 12 bytes (96-bit)
            2. Chuyển context thành AAD bytes (nếu có)
            3. Mã hóa bằng AES-256-GCM với AAD
            4. Trả về JSON chứa ciphertext + nonce + tag + aad
        
        Lưu ý bảo mật:
            - Nonce PHẢI unique cho mỗi lần encrypt với cùng key
            - AAD được authenticate nhưng không bị mã hóa
            - Tag đảm bảo integrity của ciphertext và AAD
        """
        if not plaintext:
            return ""

        # Chuẩn bị AAD từ context (nếu có)
        aad_bytes = None
        aad_str = None
        if context:
            # Serialize context thành chuỗi deterministic (sorted)
            aad_str = str(sorted(context.items()))
            aad_bytes = aad_str.encode('utf-8')
        
        # Tạo nonce ngẫu nhiên (12 bytes = 96 bits)
        nonce = secrets.token_bytes(12)
        
        # Mã hóa bằng AES-256-GCM
        cipher = Cipher(
            algorithms.AES(self.master_key), 
            modes.GCM(nonce), 
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Thêm AAD (nếu có) - AAD không bị mã hóa nhưng được authenticate
        if aad_bytes:
            encryptor.authenticate_additional_data(aad_bytes)
        
        # Mã hóa plaintext
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        
        # Lấy authentication tag (16 bytes)
        tag = encryptor.tag
        
        # Trả về JSON với tất cả thông tin cần thiết
        result = {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'aad': aad_str  # Lưu AAD để verify khi decrypt
        }
        
        return json.dumps(result)

    def decrypt_field(self, ciphertext: str, context: Optional[Dict] = None) -> str:
        """
        Giải mã và verify AAD (nếu có)
        
        Args:
            ciphertext: JSON string chứa {"ciphertext", "nonce", "tag", "aad"}
            context: Context phải KHỚP với lúc encrypt
        
        Returns:
            Plaintext (dữ liệu gốc)
        
        Raises:
            ValueError: Nếu context không khớp hoặc ciphertext invalid
            cryptography.exceptions.InvalidTag: Nếu authentication failed (tampering)
        
        Ví dụ:
            >>> decrypted = fe.decrypt_field(encrypted, context=ctx)
            >>> print(decrypted)
            "user@example.com"
            
            # Nếu context sai → ValueError
            >>> fe.decrypt_field(encrypted, context={"user_id": "456"})
            ValueError: Context mismatch - possible tampering
        
        Flow:
            1. Parse JSON để lấy ciphertext, nonce, tag, aad
            2. Verify context khớp với AAD đã lưu
            3. Giải mã bằng AES-256-GCM với AAD
            4. Trả về plaintext
        
        Lưu ý bảo mật:
            - Context mismatch = có thể bị attack (replay, tampering)
            - InvalidTag = ciphertext hoặc AAD bị sửa đổi
            - Cần log lại mọi lần decrypt failed để investigate
        """
        if not ciphertext:
            return ""

        try:
            # Parse JSON
            data = json.loads(ciphertext)
            ciphertext_bytes = base64.b64decode(data['ciphertext'])
            nonce = base64.b64decode(data['nonce'])
            tag = base64.b64decode(data['tag'])
            stored_aad = data.get('aad')
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ValueError(f"Invalid ciphertext format: {e}")

        # Verify context khớp với AAD đã lưu
        if context:
            expected_aad = str(sorted(context.items()))
            if stored_aad != expected_aad:
                raise ValueError(
                    f"Context mismatch - possible tampering. "
                    f"Expected AAD: {expected_aad}, Got: {stored_aad}"
                )
        elif stored_aad:
            raise ValueError("Ciphertext has AAD but no context provided")

        # Chuẩn bị AAD bytes
        aad_bytes = stored_aad.encode('utf-8') if stored_aad else None
        
        # Giải mã bằng AES-256-GCM
        cipher = Cipher(
            algorithms.AES(self.master_key), 
            modes.GCM(nonce, tag), 
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Authenticate AAD (nếu có)
        if aad_bytes:
            decryptor.authenticate_additional_data(aad_bytes)
        
        # Giải mã và verify tag
        try:
            plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed - data may be corrupted or tampered: {e}")


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
        - Masking KHÔNG phải là mã hóa (không thể unmask để lấy lại bản gốc)
    """
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
        # FieldEncryption expects base64-encoded string OR raw bytes
        # Pass base64-encoded string (standard base64, not urlsafe)
        self.encryption = FieldEncryption(base64.b64encode(encryption_key).decode())

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
    """Tạo AES-256 key (32 bytes) và encode thành base64"""
    return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')


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

if __name__ == "__main__":
    # AES-256-GCM + AAD
    print("===== FieldEncryption (AES-256-GCM) =====")
    fe = FieldEncryption()
    ctx = {"user_id": "1", "field": "email"}
    c = fe.encrypt_field("user@example.com", ctx)
    print("Encrypted:", c)
    print("Decrypted:", fe.decrypt_field(c, ctx), '\n')

    # Masking
    print("===== Masking =====")
    print(DataMasking.mask_card_number("4111 1111 1111 1111"))
    print(DataMasking.mask_email("user@example.com"))
    print(DataMasking.mask_phone("+84901234567"), '\n')

    # AES-GCM + AAD (standalone utility)
    print("===== AESEncryption (standalone) =====")
    key = AESEncryption.generate_key()
    print("Key:", key)
    aad = b"user_id=1"
    pack = AESEncryption.encrypt_aes_gcm("hello", key, aad)
    print("Encrypted:", pack)
    print("Decrypted:", AESEncryption.decrypt_aes_gcm(pack, key, aad), '\n')

    # PBKDF2
    print("===== Key Derivation =====")
    d = KeyDerivation.derive_key_from_password("s3cret!")
    print(d, KeyDerivation.verify_password_key("s3cret!", d["salt"], d["key"]), '\n')

    # SecureStorage
    print("===== Secure Storage =====")
    ss = SecureStorage(AESEncryption.generate_key())
    blob = ss.store_secure({"card_number":"4111111111111111","name":"Phuc"}, "user-1")
    print("Stored:", blob)
    print("Retrieved:", ss.retrieve_secure(blob))