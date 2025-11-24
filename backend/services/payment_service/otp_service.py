"""
OTP Service for Payment Gateway
Gửi mã OTP qua Gmail để xác thực thanh toán (2FA)
"""
import smtplib
import secrets
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()

# Configuration
GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
OTP_EXPIRY_SECONDS = 300  # 5 minutes
OTP_LENGTH = 6


class OTPService:
    """
    Service gửi và xác thực OTP qua Gmail
    """
    
    def __init__(self, redis_client=None):
        """
        Args:
            redis_client: Redis client để lưu OTP (nếu có)
        """
        self.redis_client = redis_client
        self.otp_storage = {}  # Fallback nếu không có Redis
        
        if not GMAIL_USER or not GMAIL_APP_PASSWORD:
            print("⚠️ Warning: GMAIL_USER or GMAIL_APP_PASSWORD not configured. OTP feature disabled.")
    
    def generate_otp(self) -> str:
        """
        Tạo mã OTP 6 chữ số ngẫu nhiên
        
        Returns:
            str: Mã OTP (VD: "123456")
        """
        return ''.join([str(secrets.randbelow(10)) for _ in range(OTP_LENGTH)])
    
    def send_otp(self, email: str, amount: float, currency: str, order_id: str) -> Optional[str]:
        """
        Gửi OTP qua Gmail
        
        Args:
            email: Email người nhận
            amount: Số tiền giao dịch
            currency: Đơn vị tiền tệ (vnd/usd)
            order_id: Mã đơn hàng
            
        Returns:
            str: OTP đã gửi (để lưu vào Redis)
            None: Nếu gửi thất bại
        """
        if not GMAIL_USER or not GMAIL_APP_PASSWORD:
            print("❌ OTP disabled: Gmail credentials not configured")
            return None
        
        # Generate OTP
        otp = self.generate_otp()
        
        # Format số tiền
        if currency.lower() == "vnd":
            amount_str = f"{int(amount):,} VNĐ"
        else:
            amount_str = f"${amount:.2f} USD"
        
        # Tạo email content
        subject = f"🔒 Mã xác thực thanh toán - {order_id}"
        
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
                .container {{ background-color: white; padding: 30px; border-radius: 10px; max-width: 500px; margin: 0 auto; }}
                .header {{ text-align: center; color: #2c3e50; margin-bottom: 20px; }}
                .otp-box {{ background-color: #3498db; color: white; font-size: 32px; font-weight: bold; 
                           text-align: center; padding: 20px; border-radius: 5px; letter-spacing: 5px; margin: 20px 0; }}
                .info {{ color: #555; line-height: 1.6; margin: 15px 0; }}
                .warning {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0; }}
                .footer {{ text-align: center; color: #888; font-size: 12px; margin-top: 30px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>🔒 Xác Thực Thanh Toán</h2>
                </div>
                
                <p class="info">Xin chào,</p>
                <p class="info">Bạn đang thực hiện giao dịch thanh toán với thông tin sau:</p>
                
                <div class="info" style="background-color: #f8f9fa; padding: 15px; border-radius: 5px;">
                    <strong>📦 Mã đơn hàng:</strong> {order_id}<br>
                    <strong>💰 Số tiền:</strong> {amount_str}
                </div>
                
                <p class="info">Vui lòng nhập mã OTP sau để xác nhận thanh toán:</p>
                
                <div class="otp-box">
                    {otp}
                </div>
                
                <div class="warning">
                    ⏱️ Mã OTP có hiệu lực trong <strong>5 phút</strong>.<br>
                    🔐 Không chia sẻ mã này với bất kỳ ai!
                </div>
                
                <p class="info">Nếu bạn không thực hiện giao dịch này, vui lòng bỏ qua email này hoặc liên hệ hỗ trợ ngay.</p>
                
                <div class="footer">
                    <p>Email này được gửi tự động từ Payment Gateway<br>
                    © 2025 NT219 Payment System</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        try:
            # Tạo message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = GMAIL_USER
            msg['To'] = email
            
            # Attach HTML
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            # Kết nối SMTP Gmail
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
                server.send_message(msg)
            
            print(f"✅ OTP sent to {email}: {otp}")
            
            # Lưu OTP vào Redis hoặc memory
            self._store_otp(email, otp, order_id)
            
            return otp
            
        except Exception as e:
            print(f"❌ Failed to send OTP: {e}")
            traceback.print_exc()
            return None
    
    def _store_otp(self, email: str, otp: str, order_id: str):
        """
        Lưu OTP vào Redis hoặc memory với TTL
        
        Args:
            email: Email người dùng
            otp: Mã OTP
            order_id: Mã đơn hàng
        """
        key = f"otp:{email}:{order_id}"
        
        if self.redis_client:
            try:
                # Lưu vào Redis với TTL 5 phút
                self.redis_client.setex(key, OTP_EXPIRY_SECONDS, otp)
                print(f"✅ OTP stored in Redis: {key}")
            except Exception as e:
                print(f"⚠️ Redis storage failed, using memory: {e}")
                self.otp_storage[key] = {
                    "otp": otp,
                    "expires_at": time.time() + OTP_EXPIRY_SECONDS
                }
        else:
            # Fallback: memory storage
            self.otp_storage[key] = {
                "otp": otp,
                "expires_at": time.time() + OTP_EXPIRY_SECONDS
            }
    
    def verify_otp(self, email: str, order_id: str, otp_input: str) -> bool:
        """
        Xác thực OTP
        
        Args:
            email: Email người dùng
            order_id: Mã đơn hàng
            otp_input: Mã OTP người dùng nhập
            
        Returns:
            bool: True nếu OTP đúng và còn hiệu lực
        """
        key = f"otp:{email}:{order_id}"
        
        # Kiểm tra Redis trước
        if self.redis_client:
            try:
                stored_otp = self.redis_client.get(key)
                if stored_otp:
                    if stored_otp == otp_input:
                        # OTP đúng → xóa khỏi Redis
                        self.redis_client.delete(key)
                        print(f"✅ OTP verified and consumed: {key}")
                        return True
                    else:
                        print(f"❌ Invalid OTP: expected={stored_otp}, got={otp_input}")
                        return False
                else:
                    print(f"❌ OTP not found or expired: {key}")
                    return False
            except Exception as e:
                print(f"⚠️ Redis verify failed: {e}")
        
        # Fallback: memory storage
        if key in self.otp_storage:
            stored = self.otp_storage[key]
            
            # Check expiry
            if time.time() > stored["expires_at"]:
                del self.otp_storage[key]
                print(f"❌ OTP expired: {key}")
                return False
            
            # Check OTP
            if stored["otp"] == otp_input:
                del self.otp_storage[key]
                print(f"✅ OTP verified (memory): {key}")
                return True
            else:
                print(f"❌ Invalid OTP (memory)")
                return False
        
        print(f"❌ OTP not found: {key}")
        return False


# Global instance (sẽ được khởi tạo với Redis từ payment.py)
otp_service: Optional[OTPService] = None


def init_otp_service(redis_client=None):
    """
    Khởi tạo OTP service
    
    Args:
        redis_client: Redis client instance
    """
    global otp_service
    otp_service = OTPService(redis_client)
    return otp_service
