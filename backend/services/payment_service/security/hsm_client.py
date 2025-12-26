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
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# -----------------------
# Cau hinh tu bien moi truong
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
# Nap thu vien PKCS#11
# -----------------------
lib = None
if pkcs11 is not None:
    try:
        if not SOFTHSM_LIB:
            raise RuntimeError("Chua cau hinh duong dan thu vien SoftHSM2 phu hop cho he dieu hanh nay.")
        lib = pkcs11.lib(SOFTHSM_LIB)
    except Exception as e:
        logger.warning("Khong the tai thu vien PKCS#11: %s", e)
        lib = None
else:
    logger.warning("Chua cai python-pkcs11; cac chuc nang HSM se khong kha dung.")


# -----------------------
# Lop loi rieng
# -----------------------
class HSMError(RuntimeError):
    """Loi tu HSM (hien thi tieng Viet)."""
    pass


def ensure_lib():
    if lib is None:
        raise HSMError(
            f"Khong the tai thu vien PKCS#11. "
            f"Vui long kiem tra bien moi truong SOFTHSM_LIB (hien tai: '{SOFTHSM_LIB}') "
            "va dam bao da cai goi python-pkcs11."
        )


def list_tokens() -> list:
    ensure_lib()
    tokens = []
    try:
        for token in lib.get_tokens():
            tokens.append({"label": token.label, "serial": token.serial})
    except Exception as e:
        logger.exception("Error listing tokens: %s", e)
        raise HSMError(f"Error listing tokens: {e}")
    return tokens


def get_session(token_label: Optional[str] = None, user_pin: Optional[str] = None, rw=True):
    ensure_lib()
    tlabel = token_label or TOKEN_LABEL
    upin = user_pin or USER_PIN
    try:
        token = lib.get_token(token_label=tlabel)
    except Exception as e:
        logger.exception("Token '%s' not found or cannot be opened: %s", tlabel, e)
        raise HSMError(f"Token '{tlabel}' not found or cannot be opened: {e}")
    try:
        session = token.open(user_pin=upin, rw=rw)
        return session
    except Exception as e:
        logger.exception("Khong the mo session tren token '%s': %s", tlabel, e)
        raise HSMError(f"Khong the mo phien lam viec tren token '{tlabel}': {e}")


def generate_rsa_keypair(label: str = "MyRSAKey"):
    with get_session(rw=True) as session:
        existing_keys = list(session.get_objects({
            Attribute.LABEL: label,
            Attribute.CLASS: ObjectClass.PRIVATE_KEY
        }))
        if existing_keys:
            print(f"Khoa '{label}' da ton tai - bo qua buoc tao moi.")
            return None, existing_keys[0]
        pub, priv = session.generate_keypair(
            KeyType.RSA, DEFAULT_RSA_BITS, store=True, label=label,
            public_template={
                Attribute.ENCRYPT: True,
                Attribute.VERIFY: True
            },
            private_template={
                Attribute.DECRYPT: True,
                Attribute.SIGN: True
            },
        )
        print(f"Da tao cap khoa voi nhan: {label}")
        return pub, priv


def sign_data(data: bytes, keylabel: str = "MyRSAKey", mechanism: Optional[Mechanism] = None) -> str:
    ensure_lib()
    try:
        with get_session(rw=False) as session:
            priv = session.get_key(
                label=keylabel,
                key_type=KeyType.RSA,
                object_class=ObjectClass.PRIVATE_KEY
            )
            mecha = mechanism or Mechanism.SHA256_RSA_PKCS
            signature = priv.sign(data, mechanism=mecha)
            return base64.b64encode(signature).decode()
    except Exception as e:
        logger.exception("Loi khi ki du lieu voi khoa '%s': %s", keylabel, e)
        raise HSMError(f"Loi khi ki du lieu bang khoa '{keylabel}': {e}")


def decrypt_data(cipher_text: bytes, keylabel: str = "MyRSAKey", mechanism: Optional[Mechanism] = None) -> bytes:
    ensure_lib()
    try:
        with get_session(rw=False) as session:
            priv = session.get_key(
                label=keylabel,
                key_type=KeyType.RSA,
                object_class=ObjectClass.PRIVATE_KEY
            )
            return priv.decrypt(cipher_text, mechanism=mechanism)
    except Exception as e:
        logger.exception("Loi khi giai ma voi khoa '%s': %s", keylabel, e)
        raise HSMError(f"Loi khi giai ma bang khoa '{keylabel}': {e}")


def generate_secure_random(num_bytes: int = 16) -> str:
    ensure_lib()
    if num_bytes <= 0:
        raise HSMError("So bytes phai lon hon 0.")
    try:
        with get_session(rw=False) as session:
            rnd = session.generate_random(num_bytes)
            return base64.b64encode(rnd).decode()
    except Exception as e:
        logger.exception("Loi khi sinh so ngau nhien: %s", e)
        raise HSMError(f"Loi khi sinh so ngau nhien: {e}")


if __name__ == "__main__":
    print("Kiem tra hoat dong cua HSM:")
    try:
        if lib is None:
            raise HSMError("Thu vien PKCS#11 chua duoc tai, hay kiem tra bien moi truong.")
        print("Thu vien duoc tai tu: ", ENV_SOFTLIB)
        print("Danh sach token: ", list_tokens())
        
        key_label = "NewDemoKey"
        generate_rsa_keypair(key_label)
        
        rnd = generate_secure_random(16)
        print("Random Number: ", rnd)
        
        sign = sign_data(b"Hello Capstone Projects", key_label)
        print("Chu ki: ", sign)
        
    except HSMError as e:
        print(f"HSM Error: {e}")
    except Exception as e:
        print(f"Xay ra loi khong xac dinh: {e}")