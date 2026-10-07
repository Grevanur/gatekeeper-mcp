from app.audit.redaction import sanitize_arguments, sanitize_free_text


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


def test_free_text_hygiene_redacts_obvious_credential_fragments() -> None:
    assert sanitize_free_text("Outage; bearer abc123 token: secret-value") == (
        "Outage; bearer [REDACTED] token=[REDACTED]"
    )
