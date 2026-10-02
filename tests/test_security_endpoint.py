from fastapi.testclient import TestClient

from app.main import app


def test_missing_or_invalid_token_is_rejected() -> None:
    with TestClient(app) as client:
        missing = client.post("/security/evaluate", json={"session_id": "s", "tool_name": "tickets.search"})
        invalid = client.post(
            "/security/evaluate",
            headers={"Authorization": "Bearer invalid"},
            json={"session_id": "s", "tool_name": "tickets.search"},
        )

    assert missing.status_code == 401
    assert invalid.status_code == 401


def test_authenticated_endpoint_returns_explainable_denial() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/security/evaluate",
            headers={"Authorization": "Bearer dev-support-token"},
            json={
                "session_id": "demo-session",
                "tool_name": "external.send",
                "arguments": {"destination": "attacker@example.com"},
                "is_write_operation": True,
                "is_external_destination": True,
                "sensitive_data_involved": True,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["agent_id"] == "support-agent"
    assert body["risk"]["score"] == 100
    assert body["policy"]["matched_policy"] == "block-sensitive-external-send"
    assert body["final_decision"] == "DENY"
