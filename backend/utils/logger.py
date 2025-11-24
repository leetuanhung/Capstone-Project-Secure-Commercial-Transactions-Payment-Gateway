from argparse import FileType
import logging
import logging.handlers
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from xml.sax import handler


# Đường dẫn thư mục logs (tự động tạo nếu chưa có)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Log levels
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Log file names
LOG_FILES = {
    "application": LOG_DIR / "application.log",
    "security": LOG_DIR / "security.log",
    "transactions": LOG_DIR / "transactions.log",
    "audit": LOG_DIR / "audit.log",
    "errors": LOG_DIR / "errors.log",
}

# Rotation settings
MAX_BYTES = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 10  # Keep 10 backup files

# ============================
# SENSITIVE DATA FILTER
# ============================


class SensitiveDataFilter(logging.Filter):
    """Redact sensitive data from logs"""

    PATTERNS = {
        "card_number": re.compile(r"\b\d{13,19}\b"),
        "cvv": re.compile(r"\bcvv[:\s=]*\d{3,4}\b", re.IGNORECASE),
        "password": re.compile(r"\bpassword[:\s=]*\S+\b", re.IGNORECASE),
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "api_key": re.compile(r"(sk_|pk_|Bearer\s+)[A-Za-z0-9_-]+", re.IGNORECASE),
    }

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._redact(record.msg)

        if record.args:
            record.args = tuple(
                self._redact(str(arg)) if isinstance(arg, str) else arg
                for arg in record.args
            )

        return True

    def _redact(self, text: str) -> str:
        # Mask card numbers
        text = self.PATTERNS["card_number"].sub(
            lambda m: "*" * (len(m.group()) - 4) + m.group()[-4:], text
        )
        # Remove CVV
        text = self.PATTERNS["cvv"].sub("[CVV_REDACTED]", text)
        # Remove passwords
        text = self.PATTERNS["password"].sub("password=[REDACTED]", text)

        # Mask emails
        def mask_email(match):
            email = match.group()
            if "@" not in email:
                return "***"
            local, domain = email.split("@")
            return f"{local[0]}***@{domain}"

        text = self.PATTERNS["email"].sub(mask_email, text)
        # Mask API keys
        text = self.PATTERNS["api_key"].sub(r"\1***", text)

        return text

# format log
class JsonFormatter(logging.Formatter):

    def format(self, record: logging.LogRecord):
        log_data = {
            "timestamp": datetime.utcnow(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        for key in ["user_id", "transaction_id", "ip_address", "order_id"]:
            if hasattr(record, key):
                log_data[key] = getattr(record, key)

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, ensure_ascii=False, default=str)


class ColoredFormatter(logging.Formatter):
    """Colored console output for better readability"""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)

"""
- log_file: duong dan den tep se duoc thuc thi
- level: (debug, info, warning, error)

"""

def setup_file_handler(
    log_file: Path, level: int = logging.INFO, use_json: bool = True
):
    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
    )
    # Khi dat kich thuc toi da thi xoay vong

    handler.setLevel(level)
    
    if use_json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        
    handler.addFilter(SensitiveDataFilter())
    return handler

def setup_console_handler(level: int = logging.INFO):
    handler = logging.StreamHandler()
    handler.setLevel(level)
    
    formatter = ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    handler.addFilter(SensitiveDataFilter())
    
    return handler

def get_logger(
    name: str,
    level: Optional[str] = None,
    console: bool = True,
    file_type: str = 'application'
):
    logger = logging.getLogger(name)
    
    log_level = getattr(logging, level or LOG_LEVEL,logging.INFO)
    logger.setLevel(log_level)
    
    if logger.handlers:
        return logger
    
    if console:
        logger.addHandler(setup_console_handler(log_level))
        
    if file_type in LOG_FILES:
        logger.addHandler(setup_file_handler(
                          LOG_FILES[file_type],
                          log_level,
                          use_json = True))
        
        return logger
    
def get_application_logger(name: str = 'app'):
    
    return get_logger(name, file_type = 'application', console = True)

def get_security_logger(name: str = 'security'):
    
    return get_logger(name, file_type='security')

def get_transaction_logger(name: str = 'transaction'):
    
    return get_logger(name, file_type='transactions', console = True)

def get_audit_logger(name: str = 'audit'):
    
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(
            LOG_FILES['audit'],
            mode = 'a',
            encoding = 'utf-8'
        )
        
        handler.setFormatter(JsonFormatter())
        handler.addFilter(SensitiveDataFilter())
        logger.addHandler(handler)

        logger.addHandler(setup_console_handler())
        
    return logger        
        
def get_error_logger(name: str = 'error'):
    
    return get_logger(name, level = 'ERROR', FileType = 'errors', console = True)

def log_payment_attempt(
    transaction_id: str,
    order_id: str,
    amount: float,
    currency: str,
    status: str,
    **kwargs
):
    logger = get_application_logger()
    logger.info(
        f"Payment {status}",
        extra={
            'transaction_id': transaction_id,
            'order_id': order_id,
            'amount': amount,
            'currency': currency,
            'status': status,
            **kwargs
        }
    )
    
def log_security_event(
    event_type: str,
    severity: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict] = None
):
    logger = get_security_logger()
    
    log_func = {
        'debug': logger.debug,
        'info': logger.info,
        'warning': logger.warning,
        'error': logger.error,
        'critical': logger.critical
    }.get(severity.lower(), logger.info)
    
    log_func(
        f"Security: {event_type}",
        extra={
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            **(details or {})
        }
    )
    
def log_audit_trail(
    action: str,
    actor_user_id: str,
    target: str,
    details: Optional[Dict] = None
):
    logger = get_audit_logger()
    logger.info(
        f"Audit: {action}",
        extra={
            'action': action,
            'actor': actor_user_id,
            'target': target,
            **(details or {})
        }
    )
    
def init_logging():
    
    for log_name, log_file in LOG_FILES.items():
        if not log_file.exists():
            log_file.touch()