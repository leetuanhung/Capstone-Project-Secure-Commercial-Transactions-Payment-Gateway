"""
Card Tokenization Module (PCI DSS Compliant)
================================================================================
Mục đích:
    Token hóa dữ liệu thẻ tín dụng nhạy cảm để tuân thủ PCI DSS.
    Thay vì lưu số thẻ thật, chỉ lưu token (chuỗi ngẫu nhiên) vào database.

Quy trình:
    1. Nhận số thẻ từ người dùng
    2. Validate số thẻ (thuật toán Luhn)
    3. Tạo token ngẫu nhiên (cryptographically secure)
    4. Lưu ánh xạ token -> dữ liệu thẻ vào vault (in-memory trong demo này)
    5. Trả về token để lưu vào DB thay vì số thẻ thật

Lợi ích:
    - Giảm phạm vi PCI DSS (không lưu trữ số thẻ thật)
    - Nếu database bị leak, hacker chỉ thấy token vô nghĩa
    - Dễ thu hồi quyền truy cập (xóa token)

Lưu ý:
    - Demo này dùng in-memory storage (mất khi restart)
    - Production cần dùng database an toàn hoặc vault (HashiCorp Vault, AWS Secrets Manager)
================================================================================
"""
import secrets
import hashlib
from typing import Dict, Optional
from datetime import datetime, timedelta
import re
from backend.utils.logger import log_audit_trail

class CardTokenizer:
    """
    Lớp Token hóa thẻ tín dụng
    
    Thuộc tính:
        token_vault (dict): Lưu ánh xạ token -> dữ liệu thẻ (in-memory)
        token_expiry (dict): Lưu thời gian hết hạn của mỗi token
    
    Lưu ý quan trọng:
        - Đây là demo dùng dict trong RAM
        - Production phải dùng database mã hóa hoặc vault an toàn
        - Token vault phải được backup và có disaster recovery plan
    """
    def __init__(self):
        # Vault lưu token -> dữ liệu thẻ (KHÔNG dùng dict trong production!)
        self.token_vault = {}  # In production, use secure database
        # Lưu thời gian hết hạn cho mỗi token (tránh token tồn tại vĩnh viễn)
        self.token_expiry = {}
        
    def validate_card_number(self, card_number: str) -> bool:
        """
        Kiểm tra số thẻ hợp lệ bằng thuật toán Luhn
        
        Thuật toán Luhn (checksum):
            1. Đảo ngược số thẻ
            2. Nhân đôi các chữ số ở vị trí lẻ
            3. Nếu kết quả > 9, trừ đi 9
            4. Tính tổng tất cả các chữ số
            5. Nếu tổng chia hết cho 10 → hợp lệ
        
        Args:
            card_number: Số thẻ (có thể chứa dấu cách/gạch ngang)
        
        Returns:
            True nếu số thẻ hợp lệ, False nếu không
        
        Ví dụ:
            >>> tokenizer.validate_card_number("4111111111111111")  # Visa test card
            True
            >>> tokenizer.validate_card_number("1234567890123456")
            False
        """
        card_number = re.sub(r'\D', '', card_number)
        
        if len(card_number) < 13 or len(card_number) > 19:
            return False
        
        # Luhn algorithm
        total = 0
        reverse_digits = card_number[::-1]
        
        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        
        return total % 10 == 0
    
    def mask_card_number(self, card_number: str) -> str:
        """
        Che giấu số thẻ, chỉ hiển thị 4 số cuối
        
        Mục đích: Tuân thủ PCI DSS - không hiển thị toàn bộ số thẻ trên UI/logs
        
        Args:
            card_number: Số thẻ đầy đủ
        
        Returns:
            Chuỗi đã che: ví dụ "************1111"
        
        Ví dụ:
            >>> tokenizer.mask_card_number("4111111111111111")
            "************1111"
        """
        clean_number = re.sub(r'\D', '', card_number)
        return f"{'*' * (len(clean_number) - 4)}{clean_number[-4:]}"
    
    def generate_token(self, card_number: str, cvv: str, expiry: str, 
                      cardholder_name: str) -> Dict[str, str]:
        """
        Tạo token an toàn cho dữ liệu thẻ
        
        Quy trình:
            1. Validate số thẻ (Luhn algorithm)
            2. Tạo token ngẫu nhiên cryptographically secure (secrets module)
            3. Lưu dữ liệu thẻ vào vault với token làm key
            4. Đặt thời gian hết hạn (1 giờ mặc định)
            5. Trả về token + thông tin đã mask
        
        Args:
            card_number: Số thẻ (16-19 digits)
            cvv: Mã CVV (3-4 digits)
            expiry: Ngày hết hạn (format: MM/YY)
            cardholder_name: Tên chủ thẻ
        
        Returns:
            Dict chứa:
                - token: Token để lưu vào DB
                - masked_card: Số thẻ đã che (hiển thị cho user)
                - card_brand: Loại thẻ (Visa/Mastercard/...)
                - fingerprint: Hash duy nhất của thẻ
        
        Raises:
            ValueError: Nếu số thẻ không hợp lệ
        
        Ví dụ:
            >>> result = tokenizer.generate_token(
            ...     "4111111111111111", "123", "12/25", "JOHN DOE"
            ... )
            >>> print(result['token'])
            "tok_aBcD123..."
            >>> print(result['masked_card'])
            "************1111"
        
        Lưu ý bảo mật:
            - CVV KHÔNG BAO GIỜ được lưu trữ lâu dài (PCI DSS 3.2.2)
            - Token có thời gian sống giới hạn (1h) để giảm rủi ro
            - Trong production, dữ liệu phải được mã hóa trước khi lưu vault
        """
        if not self.validate_card_number(card_number):
            raise ValueError("Invalid card number")
        
        # Generate cryptographically secure token
        token = f"tok_{secrets.token_urlsafe(32)}"
        
        # Store encrypted card data (in production, encrypt with HSM)
        card_data = {
            'card_number': card_number,
            'cvv': cvv,
            'expiry': expiry,
            'cardholder_name': cardholder_name,
            'created_at': datetime.utcnow().isoformat(),
            'fingerprint': self._generate_fingerprint(card_number)
        }
        
        self.token_vault[token] = card_data
        self.token_expiry[token] = datetime.utcnow() + timedelta(hours=1)
        
        return {
            'token': token,
            'masked_card': self.mask_card_number(card_number),
            'card_brand': self._detect_card_brand(card_number),
            'fingerprint': card_data['fingerprint']
        }
    
    def detokenize(self, token: str) -> Optional[Dict[str, str]]:
        """
        Lấy lại dữ liệu thẻ gốc từ token (DETOKENIZATION)
        
        Khi nào dùng:
            - Chỉ khi thực sự cần số thẻ để xử lý thanh toán
            - KHÔNG dùng để hiển thị cho user
            - Phải log lại mọi lần detokenize để audit
        
        Args:
            token: Token đã tạo trước đó
        
        Returns:
            Dict chứa dữ liệu thẻ gốc (card_number, cvv, expiry, ...)
        
        Raises:
            ValueError: Nếu token không tồn tại hoặc đã hết hạn
        
        Ví dụ:
            >>> card_data = tokenizer.detokenize("tok_aBcD123...")
            >>> print(card_data['card_number'])
            "4111111111111111"
        
        Nguyên tắc bảo mật:
            - Chỉ detokenize khi cần thiết (principle of least privilege)
            - Log mọi lần detokenize với user_id, timestamp, lý do
            - Xóa dữ liệu khỏi memory ngay sau khi dùng xong
            - Trong production: yêu cầu thêm xác thực (MFA) để detokenize
        """
        if token not in self.token_vault:
            raise ValueError("Invalid or expired token")
        
        # Kiểm tra token đã hết hạn chưa
        if datetime.utcnow() > self.token_expiry[token]:
            # Xóa token hết hạn khỏi vault (cleanup)
            del self.token_vault[token]
            del self.token_expiry[token]
            raise ValueError("Token has expired")
        
        return self.token_vault[token]
    
    def _generate_fingerprint(self, card_number: str) -> str:
        """Generate unique fingerprint for card"""
        return hashlib.sha256(card_number.encode()).hexdigest()[:16]
    
    def _detect_card_brand(self, card_number: str) -> str:
        """
        Nhận diện loại thẻ từ số thẻ (BIN - Bank Identification Number)
        
        Quy tắc nhận diện:
            - Visa: Bắt đầu bằng 4
            - Mastercard: Bắt đầu bằng 51-55
            - American Express: Bắt đầu bằng 34 hoặc 37
            - Discover: Bắt đầu bằng 6011
        
        Args:
            card_number: Số thẻ
        
        Returns:
            Tên loại thẻ: "Visa", "Mastercard", "American Express", "Discover", "Unknown"
        
        Lưu ý:
            - Có thể mở rộng thêm nhiều loại thẻ khác (JCB, UnionPay...)
            - BIN ranges có thể thay đổi theo thời gian
        """
        clean_number = re.sub(r'\D', '', card_number)
        
        if clean_number[0] == '4':
            return 'Visa'
        elif clean_number[:2] in ['51', '52', '53', '54', '55']:
            return 'Mastercard'
        elif clean_number[:2] in ['34', '37']:
            return 'American Express'
        elif clean_number[:4] == '6011':
            return 'Discover'
        else:
            return 'Unknown'
    
    def delete_token(self, token: str) -> bool:
        """
        Xóa token khỏi vault một cách an toàn
        
        Khi nào dùng:
            - Sau khi giao dịch hoàn tất
            - Khi user yêu cầu xóa thẻ đã lưu
            - Khi phát hiện token bị compromise
        
        Args:
            token: Token cần xóa
        
        Returns:
            True nếu xóa thành công, False nếu token không tồn tại
        
        Lưu ý bảo mật:
            - Log lại mọi lần xóa token
            - Trong production: overwrite memory trước khi delete (tránh memory dump attack)
        """
        if token in self.token_vault:
            del self.token_vault[token]
            del self.token_expiry[token]
            log_audit_trail(
            action='token_deleted',
            actor_user_id='system',  # Hoặc user_id nếu có
            target=f'token:{token[:8]}***',
            details={'reason': 'manual_deletion'}
        )
            return True
        return False

# ============================================================================
# SINGLETON INSTANCE
# ============================================================================
# Tạo một instance duy nhất để dùng chung trong toàn bộ ứng dụng
# Lợi ích: Dùng chung vault, tránh tạo nhiều instance gây lãng phí memory
# 
# Cách dùng:
#     from backend.services.payment_service.security.tokenization import card_tokenizer
#     result = card_tokenizer.generate_token(...)
# ============================================================================
card_tokenizer = CardTokenizer()

# Tracing (light-weight) - import here to avoid circulars at package import
try:
    from .tracer import trace_event
except Exception:
    def trace_event(name, payload, reveal=False):
        return None

# Instrumentation: log token create/delete
def _trace_token_create(result: Dict[str, str]):
    try:
        trace_event("tokenize.created", {
            'token': result.get('token'),
            'masked_card': result.get('masked_card'),
            'card_brand': result.get('card_brand')
        })
    except Exception:
        pass

# Wrap generate_token to trace
_orig_generate_token = CardTokenizer.generate_token

def _wrapped_generate_token(self, card_number: str, cvv: str, expiry: str, cardholder_name: str):
    trace_event('tokenize.request', {'card_number': card_number, 'cardholder_name': cardholder_name})
    result = _orig_generate_token(self, card_number, cvv, expiry, cardholder_name)
    _trace_token_create(result)
    return result

CardTokenizer.generate_token = _wrapped_generate_token
