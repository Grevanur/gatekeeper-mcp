from app.audit.redaction import sanitize_arguments


def test_redaction_recursively_removes_obvious_secret_values() -> None:
    sanitized = sanitize_arguments(
        {
            "username": "alice",
            "password": "hunter2",
            "nested": {"api_key": "abc123", "safe": "value"},
            "items": [{"access_token": "token-value"}, {"name": "visible"}],
        }
    )

    assert sanitized == {
        "username": "alice",
        "password": "[REDACTED]",
        "nested": {"api_key": "[REDACTED]", "safe": "value"},
        "items": [{"access_token": "[REDACTED]"}, {"name": "visible"}],
    }
