from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.approvals.binding import ApprovalBinding, hash_canonical
from app.approvals.identity import ApproverIdentity
from app.approvals.service import ApprovalBindingMismatchError, ApprovalService
from app.approvals.workflows import ApprovalWorkflowRegistry
from app.audit.service import AuditService
from app.database.models import Base
from app.policy.lifecycle import PolicyLifecycleService
from app.policy.models import PoliciesConfiguration


class FakeClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value

    def advance(self, days: int) -> None:
        self.value += timedelta(days=days)


def _policy(version: int = 1) -> dict:
    return {
        "id": "prod-delete-approval",
        "name": "Production delete approval",
        "description": "Requires governed approval.",
        "version": version,
        "owner": "platform-security",
        "status": "ACTIVE",
        "review": {"last_reviewed_at": "2026-01-01", "review_interval_days": 90},
        "change_reason": "Initial rule." if version == 1 else "Added fallback security approver.",
        "priority": 10,
        "match": {},
        "action": "REQUIRE_APPROVAL",
        "approval_workflow": "production-destructive-workflow",
        "reason": "Approval required.",
    }


def _approval_service() -> tuple[ApprovalService, ApprovalBinding]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    binding = ApprovalBinding.create(
        agent_id="admin-agent", session_id="session-1", gateway_tool_name="messaging.external.send",
        downstream_server="messaging", downstream_tool_name="external.send",
        arguments={"destination": "internal-security@company.com", "data": "incident-summary"},
        destination="internal-security@company.com", destination_type="email", environment="development",
        security_context={"risk_level": "HIGH", "is_external_destination": True},
        policy_id="high-risk-approval", policy_version=1,
    )
    service = ApprovalService(factory, ApprovalWorkflowRegistry.from_config_file("config/approval_workflows.yaml"))
    return service, binding


def test_canonical_hash_and_destination_binding_require_a_fresh_decision() -> None:
    assert hash_canonical({"data": "hello", "destination": "a@example.com"}) == hash_canonical(
        {"destination": "a@example.com", "data": "hello"}
    )
    service, binding = _approval_service()
    request = service.create(
        request_id="req-1", session_id="session-1", agent_id="admin-agent",
        gateway_tool_name="messaging.external.send", downstream_server="messaging",
        downstream_tool_name="external.send",
        arguments={"destination": "internal-security@company.com", "data": "incident-summary"},
        risk_score=80, risk_level="HIGH", risk_factors=[], matched_policy="high-risk-needs-approval",
        workflow_id="default-high-risk-workflow", reason="Approval required.", binding=binding,
        policy_id="high-risk-approval", policy_version=1,
    )
    service.approve(
        request.approval_id,
        ApproverIdentity(subject_id="security-admin-1", display_name="Reviewer", role="security_admin"),
    )
    changed = ApprovalBinding.create(
        agent_id="admin-agent", session_id="session-1", gateway_tool_name="messaging.external.send",
        downstream_server="messaging", downstream_tool_name="external.send",
        arguments={"destination": "external-personal@gmail.com", "data": "incident-summary"},
        destination="external-personal@gmail.com", destination_type="email", environment="development",
        security_context={"risk_level": "HIGH", "is_external_destination": True},
        policy_id="high-risk-approval", policy_version=1,
    )
    with pytest.raises(ApprovalBindingMismatchError) as error:
        service.claim_execution(request.approval_id, "admin-agent", binding=changed)
    assert error.value.code == "APPROVAL_DESTINATION_MISMATCH"
    assert "destination" in error.value.changed_fields


def test_tool_environment_and_security_context_changes_are_rejected() -> None:
    service, binding = _approval_service()
    request = service.create(
        request_id="req-2", session_id="session-1", agent_id="admin-agent",
        gateway_tool_name="messaging.external.send", downstream_server="messaging",
        downstream_tool_name="external.send",
        arguments={"destination": "internal-security@company.com", "data": "incident-summary"},
        risk_score=80, risk_level="HIGH", risk_factors=[], matched_policy="high-risk-needs-approval",
        workflow_id="default-high-risk-workflow", reason="Approval required.", binding=binding,
        policy_id="high-risk-approval", policy_version=1,
    )
    service.approve(request.approval_id, ApproverIdentity(subject_id="security-admin-1", display_name="Reviewer", role="security_admin"))
    cases = [
        (binding.model_copy(update={"gateway_tool_name": "webhook.post"}), "APPROVAL_TOOL_MISMATCH"),
        (binding.model_copy(update={"environment": "production"}), "APPROVAL_ENVIRONMENT_MISMATCH"),
        (binding.model_copy(update={"security_context_hash": "changed"}), "APPROVAL_SECURITY_CONTEXT_MISMATCH"),
    ]
    for candidate, expected_code in cases:
        with pytest.raises(ApprovalBindingMismatchError) as error:
            service.claim_execution(request.approval_id, "admin-agent", binding=candidate)
        assert error.value.code == expected_code


def test_policy_versions_are_immutable_and_stale_audits_once() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    audit = AuditService(factory)
    clock = FakeClock(datetime(2026, 1, 1, tzinfo=timezone.utc))
    first = PolicyLifecycleService(
        factory, PoliciesConfiguration.model_validate({"policies": [_policy(1)]}), audit, clock
    )
    first.synchronize()
    clock.advance(91)
    assert first.get("prod-delete-approval").review_status == "STALE"
    assert first.get("prod-delete-approval").review_status == "STALE"
    second = PolicyLifecycleService(
        factory, PoliciesConfiguration.model_validate({"policies": [_policy(2)]}), audit, clock
    )
    second.synchronize()

    history = second.history("prod-delete-approval")
    assert [item["version"] for item in history] == [1, 2]
    assert [event.event_type for event in audit.list_events()].count("POLICY_MARKED_STALE") == 1
