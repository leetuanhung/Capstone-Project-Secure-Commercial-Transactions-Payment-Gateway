"""Simple tracing utility for security modules.

Purpose:
 - Emit structured trace events (JSON lines) for key security operations
 - Redact sensitive fields (card_number, cvv) by default; can reveal with env var

Usage:
    from .tracer import trace_event
    trace_event('tokenize.request', {'card_number': '4111...'} )

Notes:
 - Traces are written to console and to a file at security_trace.log
 - This is for development/debug only; do not enable reveal in production.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict

# Configure logger for tracer
LOGGER = logging.getLogger("security_tracer")
if not LOGGER.handlers:
    LOGGER.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    fmt = logging.Formatter("%(message)s")
    ch.setFormatter(fmt)
    LOGGER.addHandler(ch)

# File logger
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "security_trace.log")
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter("%(message)s"))
LOGGER.addHandler(fh)


def _mask_card(number: str) -> str:
    if not number:
        return ""
    digits = ''.join([c for c in number if c.isdigit()])
    if len(digits) <= 4:
        return '*' * len(digits)
    return '*' * (len(digits) - 4) + digits[-4:]


def _mask_cvv(cvv: str) -> str:
    if not cvv:
        return ''
    return '***'


def _redact_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in payload.items():
        if v is None:
            out[k] = None
            continue
        kl = k.lower()
        if 'card' in kl and isinstance(v, str):
            out[k] = _mask_card(v)
        elif 'cvv' in kl or 'cvc' in kl:
            out[k] = _mask_cvv(v)
        else:
            out[k] = v
    return out


def trace_event(name: str, payload: Dict[str, Any], reveal: bool = False) -> None:
    """Emit a trace event.

    Args:
        name: short event name, e.g. 'tokenize.request'
        payload: mapping of keys/values to include
        reveal: if True, do not redact sensitive fields (dev only)
    """
    reveal_env = os.getenv("SECURITY_TRACING_REVEAL", "false").lower() in ("1", "true", "yes")
    show_all = reveal or reveal_env

    safe = payload if show_all else _redact_payload(payload)

    event = {
        'ts': datetime.utcnow().isoformat() + 'Z',
        'event': name,
        'payload': safe,
    }
    line = json.dumps(event, default=str, ensure_ascii=False)
    LOGGER.info(line)
