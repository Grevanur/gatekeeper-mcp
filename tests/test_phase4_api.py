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


def test_governance_endpoints_enforce_role_bound_approval_and_expose_timeline() -> None:
    with TestClient(app) as client:
        approval = app.state.approval_service.create(
            request_id="v2-api-request",
            session_id="v2-api-session",
            agent_id="admin-agent",
            gateway_tool_name="sensitive-data.database.delete",
            downstream_server="sensitive-data",
            downstream_tool_name="database.delete",
            arguments={"table": "temporary_records"},
            risk_score=100,
            risk_level="CRITICAL",
            risk_factors=[],
            matched_policy="production-delete-requires-approval",
            workflow_id="production-destructive-workflow",
            reason="Approval required.",
        )
        unauthorized = client.post(
            f"/approvals/{approval.approval_id}/approve",
            headers={"Authorization": "Bearer dev-security-admin-token"},
        )
        approved = client.post(
            f"/approvals/{approval.approval_id}/approve",
            headers={"Authorization": "Bearer dev-system-owner-token"},
        )
        timeline = client.get(
            f"/approvals/{approval.approval_id}/timeline",
            headers={"Authorization": "Bearer dev-reviewer-token"},
        )

    assert unauthorized.status_code == 409
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"
    assert timeline.status_code == 200
    assert {"APPROVAL_CREATED", "APPROVAL_PRIMARY_APPROVED"} <= {
        event["event_type"] for event in timeline.json()
    }
