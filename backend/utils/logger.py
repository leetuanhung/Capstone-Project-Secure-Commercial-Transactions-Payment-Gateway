import logging
import logging.handlers
import json
import os
import re
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


# Đường dẫn thư mục logs (tự động tạo nếu chưa có)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

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
        "otp": re.compile(r"\b(?:otp|code|verification_code)[:\s=]*\d{4,8}\b", re.IGNORECASE),
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

        # Redact extra fields as well (important for JSON logs)
        for key, value in list(record.__dict__.items()):
            if key.startswith("_"):
                continue
            record.__dict__[key] = self._redact_obj(value)

        return True

    def _redact_obj(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._redact(value)
        if isinstance(value, dict):
            return {k: self._redact_obj(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            redacted = [self._redact_obj(v) for v in value]
            return type(value)(redacted) if isinstance(value, tuple) else redacted
        return value

    def _redact(self, text: str) -> str:
        # Mask card numbers
        text = self.PATTERNS["card_number"].sub(
            lambda m: "*" * (len(m.group()) - 4) + m.group()[-4:], text
        )
        # Remove CVV
        text = self.PATTERNS["cvv"].sub("[CVV_REDACTED]", text)
        # Remove passwords
        text = self.PATTERNS["password"].sub("password=[REDACTED]", text)

        # Remove OTP-like values
        text = self.PATTERNS["otp"].sub("otp=[REDACTED]", text)

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


# ============================
# REQUEST CONTEXT (request_id, user_id, ip)
# ============================


_request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
_user_id_ctx: ContextVar[Optional[str]] = ContextVar("user_id", default=None)
_ip_address_ctx: ContextVar[Optional[str]] = ContextVar("ip_address", default=None)


def set_request_context(
    *,
    request_id: Optional[str] = None,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    tokens: Dict[str, Any] = {}
    tokens["request_id"] = _request_id_ctx.set(request_id)
    tokens["user_id"] = _user_id_ctx.set(user_id)
    tokens["ip_address"] = _ip_address_ctx.set(ip_address)
    return tokens


def clear_request_context(tokens: Dict[str, Any]) -> None:
    if not tokens:
        return
    _request_id_ctx.reset(tokens.get("request_id"))
    _user_id_ctx.reset(tokens.get("user_id"))
    _ip_address_ctx.reset(tokens.get("ip_address"))


class RequestContextFilter(logging.Filter):
    """Inject request-scoped context into each log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = _request_id_ctx.get()
        if not hasattr(record, "user_id"):
            record.user_id = _user_id_ctx.get()
        if not hasattr(record, "ip_address"):
            record.ip_address = _ip_address_ctx.get()
        return True

# format log
class JsonFormatter(logging.Formatter):

    def format(self, record: logging.LogRecord):
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include all non-standard extra fields
        reserved = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
        }
        for key, value in record.__dict__.items():
            if key in reserved or key.startswith("_"):
                continue
            if key in log_data:
                continue
            log_data[key] = value

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
        original_levelname = record.levelname
        try:
            record.levelname = f"{color}{record.levelname}{self.RESET}"
            return super().format(record)
        finally:
            record.levelname = original_levelname


def setup_file_handler(
    log_file: Path, level: int = logging.INFO, use_json: bool = True
):
    """Setup rotating file handler with JSON or text format"""
    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8"
    )
    handler.setLevel(level)
    
    if use_json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        
    handler.addFilter(RequestContextFilter())
    handler.addFilter(SensitiveDataFilter())
    return handler


def setup_console_handler(level: int = logging.INFO):
    """Setup console handler with colored output"""
    handler = logging.StreamHandler()
    handler.setLevel(level)
    
    formatter = ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    handler.addFilter(RequestContextFilter())
    handler.addFilter(SensitiveDataFilter())
    
    return handler


def get_logger(
    name: str,
    level: Optional[str] = None,
    console: bool = True,
    file_type: str = 'application'
):
    """
    Get or create a logger with specified configuration
    
    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        console: Enable console output
        file_type: Type of log file (application, security, transactions, audit, errors)
    
    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Set log level
    log_level = getattr(logging, level or LOG_LEVEL, logging.INFO)
    logger.setLevel(log_level)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    logger.propagate = False
    
    # Add console handler
    if console:
        logger.addHandler(setup_console_handler(log_level))
    
    # Add file handler
    if file_type in LOG_FILES:
        logger.addHandler(setup_file_handler(
            LOG_FILES[file_type],
            log_level,
            use_json=True
        ))
    
    # ✅ FIX: Return logger OUTSIDE the if block
    return logger


def get_application_logger(name: str = 'app'):
    """Get application logger (logs to application.log)"""
    return get_logger(name, file_type='application', console=True)


def get_security_logger(name: str = 'security'):
    """Get security logger (logs to security.log)"""
    return get_logger(name, file_type='security', console=True)


def get_transaction_logger(name: str = 'transaction'):
    """Get transaction logger (logs to transactions.log)"""
    return get_logger(name, file_type='transactions', console=True)


def get_audit_logger(name: str = 'audit'):
    """Get audit logger (logs to audit.log with JSON format only)"""
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    logger.setLevel(logging.INFO)
    
    # File handler (JSON only, no console)
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILES['audit'],
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding='utf-8'
    )
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestContextFilter())
    handler.addFilter(SensitiveDataFilter())
    logger.addHandler(handler)
    
    return logger


def get_error_logger(name: str = 'error'):
    """Get error logger (logs to errors.log, ERROR level only)"""
    # ✅ FIX: file_type instead of FileType
    return get_logger(name, level='ERROR', file_type='errors', console=True)


# ============================
# HIGH-LEVEL LOGGING FUNCTIONS
# ============================

def log_payment_attempt(
    transaction_id: str,
    order_id: str,
    amount: float,
    currency: str,
    status: str,
    **kwargs
):
    """Log payment attempt to application log"""
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
    """Log security event to security.log"""
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
    """Log audit trail to audit.log"""
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
    """Initialize logging system (create log files if not exist)"""
    for log_name, log_file in LOG_FILES.items():
        if not log_file.exists():
            log_file.touch()

    # Use standard logging (no prints) so output respects handlers/filters
    bootstrap_logger = get_application_logger("logging")
    bootstrap_logger.info(
        "Logging initialized",
        extra={"log_dir": str(LOG_DIR), "log_files": {k: str(v) for k, v in LOG_FILES.items()}},
    )