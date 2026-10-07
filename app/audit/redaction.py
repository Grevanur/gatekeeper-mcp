"""Basic defensive redaction for arguments persisted in audit records."""

import re
from typing import Any


_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "private_key",
)


def sanitize_arguments(value: Any) -> Any:
    """Recursively replace values whose mapping keys signal obvious secrets.

    This is logging hygiene, not a complete data-loss-prevention system.
    """

    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _is_sensitive_key(str(key)) else sanitize_arguments(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_arguments(item) for item in value]
    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def sanitize_free_text(value: str) -> str:
    """Redact obvious credential fragments from operator-entered text.

    This intentionally remains basic logging hygiene rather than full DLP.
    """

    value = re.sub(r"(?i)(bearer\s+)[^\s]+", r"\1[REDACTED]", value)
    return re.sub(
        r"(?i)\b(password|passwd|token|secret|api[_ -]?key|credential)\s*[:=]\s*\S+",
        r"\1=[REDACTED]",
        value,
    )
