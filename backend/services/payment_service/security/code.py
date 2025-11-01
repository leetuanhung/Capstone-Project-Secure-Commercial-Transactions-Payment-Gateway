import os
import base64
import logging
import platform
from typing import Optional

try:
    import pkcs11
    from pkcs11 import Attribute, KeyType, ObjectClass, Mechanism
except Exception:
    pkcs11 = None
    Attribute = KeyType = ObjectClass = Mechanism = None

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# -----------------------
# Cấu hình từ biến môi trường
# -----------------------
ENV_SOFTLIB = os.getenv("SOFTHSM_LIB", "").strip()
if ENV_SOFTLIB:
    SOFTHSM_LIB = ENV_SOFTLIB
else:
    system = platform.system()
    if system == "Windows":
        SOFTHSM_LIB = r"D:\SoftHSM2\lib\softhsm2-x64.dll"
    elif system == "Linux":
        possible = [
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/usr/lib/libsofthsm2.so",
        ]
        SOFTHSM_LIB = next((p for p in possible if os.path.exists(p)), possible[0])
    elif system == "Darwin":
        SOFTHSM_LIB = "/usr/local/lib/softhsm/libsofthsm2.dylib"
    else:
        SOFTHSM_LIB = ""

TOKEN_LABEL = os.getenv("TOKEN_LABEL", "MyToken1")
USER_PIN = os.getenv("USER_PIN", "890844")
DEFAULT_RSA_BITS = int(os.getenv("HSM_RSA_BITS", "2048"))

# -----------------------
# Nạp thư viện PKCS#11
# -----------------------
lib = None
if pkcs11 is not None:
    try:
        if not SOFTHSM_LIB:
            raise RuntimeError("Chưa cấu hình đường dẫn thư viện SoftHSM2 phù hợp cho hệ điều hành này.")
        lib = pkcs11.lib(SOFTHSM_LIB)
    except Exception as e:
        logger.warning("⚠️ Không thể tải thư viện PKCS#11: %s", e)
        lib = None
else:
    logger.warning("⚠️ Chưa cài python-pkcs11; các chức năng HSM sẽ không khả dụng.")


# -----------------------
# Lớp lỗi riêng
# -----------------------
class HSMError(RuntimeError):
    """Lỗi từ HSM (hiển thị tiếng Việt)."""
    pass


def ensure_lib():
    if lib is None:
        raise HSMError(
            f"❌ Không thể tải thư viện PKCS#11. "
            f"Vui lòng kiểm tra biến môi trường SOFTHSM_LIB (hiện tại: '{SOFTHSM_LIB}') "
            "và đảm bảo đã cài gói python-pkcs11."
        )


def list_tokens()-> list:
    ensure_lib()
    tokens = []
    try:
        for token in lib.get_tokens():
            tokens.append({"label": token.label, "serial": token.serial})
    except Exception:
        logger.exception("Error listing tokens: %s", Exception)
        raise HSMError(f"Error listing tokens: {Exception}")
    return tokens


def get_session(token_label: Optional[str] = None, user_pin: Optional[str] = None, rw = True):
    ensure_lib()
    tlabel = token_label or TOKEN_LABEL
    upin = user_pin or USER_PIN
    try:
        token = lib.get_token(token_label = tlabel)
    except Exception:
        logger.exception("Token '%s' not found or cannot be opened: %s", tlabel, Exception)
        raise HSMError(f"Token '{tlabel}' not found or cannot be opened: {Exception}")
    try:
        session = token.open(user_pin = upin, rw = True)
        return session
    except Exception:
        logger.exception("Không thể mở session trên token '%s': %s", tlabel, Exception)
        raise HSMError(f"Không thể mở phiên làm việc trên token '{tlabel}': {Exception}")
    
def generate_rsa_keypair(label: str = "MyRSAKey"):
    with get_session(rw = True) as session:
        existing_keys = list(session.get_objects({
            Attribute.LABEL: label,
            Attribute.CLASS: ObjectClass.PRIVATE_KEY
        }))
        if existing_keys:
            print(f"Khóa '{label}' đã tồn tại - bỏ qua bước tạo mới.")
            return None, existing_keys[0]
        pub, priv = session.generate_key_pair(
            KeyType.RSA, DEFAULT_RSA_BITS, store = True, label = label,
            public_template = {
                Attribute.ENCRYPT: True,
                Attribute.VERIFY: True
            },
            private_template = {
                Attribute.DECRYPT: True,
                Attribute.SIGN: True
            },
        )
        print(f"Đã tạo cặp khóa với nhãn: {label}")
        return pub, priv

def sign_data(data: bytes, keylabel: str = "MyRSAKey", mechanism: Optional[Mechanism] = None) -> str:
    ensure_lib()
    try:
        with get_session(rw = False) as session:
            priv = session.get_key(
                label = keylabel,
                key_type = KeyType.RSA,
                object_class = ObjectClass.PRIVATE_KEY
            )
            mecha = mechanism or Mechanism.SHA3_256_RSA_PKCS
            signature = priv.sign(data, mechanism = mecha)
            return base64.b64encode(signature).decode()
    except Exception:
        logger.exception("Lỗi khi kí dữ liệu với khóa '%s': %s", keylabel)
        raise HSMError(f"Lỗi khi kí dữ liệu bằng khóa '{keylabel}': {Exception}")
    
def decrypt_data(cipher_text: bytes, keylabel: str = "MyRSAKey", mechanism: Optional[Mechanism] = None) -> bytes:
    ensure_lib()
    try:
        with get_session(rw = False) as session:
            priv = session.get_key(
                lable = keylabel,
                key_type = KeyType.RSA,
                object_class = ObjectClass.PRIVATE_KEY
            )
            return priv.decrypt(cipher_text)
    except Exception:
        logger.exception("Lỗi khi giải mã với khóa '%s': %s", keylabel, Exception)
        raise HSMError(f"Lỗi khi giải mã bằng khóa '{keylabel}': {Exception}")
    
def generate_secure_random(num_bytes: int = 16) -> str:
    ensure_lib()
    if num_bytes <= 0:
        raise HSMError("Số bytes phải lớn hơn 0.")
    try:
        with get_session(rw = False) as session:
            rnd = session.generate_random(num_bytes)
            return base64.b64encode(rnd).decode()
    except Exception:
        logger.exception("Lỗi khi sinh số ngẫu nhiên ", Exception)
        raise HSMError("Lỗi khi sinh số ngẫu nhiên: ", Exception)

if __name__ == "__main__":
    print("Kiểm tra hoạt động của HSM:")
    try:
        if lib is None:
            raise HSMError("Thư viện PKCS#11 chưa được tải, hãy kiểm tra biến môi trường.")
        print("Thư viện được tải từ: ", ENV_SOFTLIB)
        print("Danh sách token: ", list_tokens())
        
        key_label= "DemoKey"
        generate_rsa_keypair(key_label)
        
        rnd = generate_secure_random(16)
        print("Randome Number: ", rnd)
        
        sign = sign_data(b"Hello Capstone Projects", key_label)
        print("Chữ kí: ", sign)
        
    except HSMError:
        print(HSMError)
    except Exception:
        print("Xảy ra lỗi không xác định: ", Exception)