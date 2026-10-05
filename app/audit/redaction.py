"""Basic defensive redaction for arguments persisted in audit records."""

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
