from fastapi.testclient import TestClient

from app.main import app


def test_operational_apis_require_admin_and_return_structured_missing_errors() -> None:
    with TestClient(app) as client:
        support_audit = client.get(
            "/audit/events", headers={"Authorization": "Bearer dev-support-token"}
        )
        reviewer_approvals = client.get(
            "/approvals", headers={"Authorization": "Bearer dev-reviewer-token"}
        )
        missing_approval = client.get(
            "/approvals/apr_missing", headers={"Authorization": "Bearer dev-reviewer-token"}
        )
        missing_session = client.get(
            "/sessions/no-such-session", headers={"Authorization": "Bearer dev-support-token"}
        )

    assert support_audit.status_code == 403
    assert reviewer_approvals.status_code == 200
    assert missing_approval.status_code == 404
    assert missing_approval.json()["code"] == "APPROVAL_NOT_FOUND"
    assert missing_session.status_code == 404
    assert missing_session.json()["code"] == "SESSION_NOT_FOUND"
