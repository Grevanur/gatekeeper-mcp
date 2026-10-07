from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.approvals.identity import ApproverIdentity
from app.approvals.models import ApprovalStatus
from app.approvals.service import (
    ApprovalAlreadyConsumedError,
    ApprovalArgumentMismatchError,
    ApprovalDeniedError,
    ApprovalExpiredError,
    ApprovalService,
    ApprovalTimedOutError,
)
from app.approvals.workflows import ApprovalWorkflowRegistry
from app.audit.service import AuditService
from app.database.models import Base


class FakeClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


SYSTEM_OWNER = ApproverIdentity(subject_id="system-owner-1", display_name="Owner", role="system_owner")
SECURITY_ADMIN = ApproverIdentity(subject_id="security-admin-1", display_name="Admin", role="security_admin")
SECURITY_LEAD = ApproverIdentity(subject_id="security-lead-1", display_name="Lead", role="security_lead")


def _service() -> tuple[ApprovalService, AuditService, FakeClock]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    audit = AuditService(factory)
    clock = FakeClock()
    return ApprovalService(factory, ApprovalWorkflowRegistry.from_config_file("config/approval_workflows.yaml"), audit, clock), audit, clock


def _approval(service: ApprovalService, workflow_id: str = "production-destructive-workflow"):
    return service.create(
        request_id="req-1", session_id="session-1", agent_id="admin-agent",
        gateway_tool_name="sensitive-data.database.delete", downstream_server="sensitive-data",
        downstream_tool_name="database.delete", arguments={"table": "temporary_records"},
        risk_score=100, risk_level="CRITICAL", risk_factors=[],
        matched_policy="high-risk-needs-approval", workflow_id=workflow_id, reason="Approval required.",
    )


def test_primary_role_approves_bound_request_and_executes_once() -> None:
    service, _, _ = _service()
    request = _approval(service)
    assert service.approve(request.approval_id, SYSTEM_OWNER).status is ApprovalStatus.APPROVED
    claim = service.claim_execution(request.approval_id, "admin-agent", {"table": "temporary_records"})
    assert claim.original_arguments == {"table": "temporary_records"}
    assert service.complete_execution(request.approval_id, True, "admin-agent").status is ApprovalStatus.EXECUTED
    with pytest.raises(ApprovalAlreadyConsumedError):
        service.claim_execution(request.approval_id, "admin-agent")


def test_unauthorized_primary_and_wrong_bindings_are_blocked() -> None:
    service, _, _ = _service()
    request = _approval(service)
    with pytest.raises(ApprovalDeniedError):
        service.approve(request.approval_id, SECURITY_ADMIN)
    service.approve(request.approval_id, SYSTEM_OWNER)
    with pytest.raises(ApprovalArgumentMismatchError):
        service.claim_execution(request.approval_id, "admin-agent", {"table": "customers"})
    with pytest.raises(ApprovalDeniedError):
        service.claim_execution(request.approval_id, "other-agent")


def test_primary_timeout_escalates_and_fallback_approves_once() -> None:
    service, audit, clock = _service()
    request = _approval(service)
    clock.advance(901)
    fallback = service.get(request.approval_id)
    assert fallback.status is ApprovalStatus.PENDING_FALLBACK
    with pytest.raises(ApprovalDeniedError):
        service.approve(request.approval_id, SYSTEM_OWNER)
    assert service.approve(request.approval_id, SECURITY_ADMIN).approved_by == "security-admin-1"
    service.claim_execution(request.approval_id, "admin-agent")
    assert service.complete_execution(request.approval_id, True, "admin-agent").status is ApprovalStatus.EXECUTED
    assert "APPROVAL_ESCALATED" in {event.event_type for event in audit.list_events(approval_id=request.approval_id)}


def test_exhausted_workflow_fails_closed_without_execution() -> None:
    service, audit, clock = _service()
    request = _approval(service)
    clock.advance(901)
    assert service.get(request.approval_id).status is ApprovalStatus.PENDING_FALLBACK
    clock.advance(901)
    assert service.get(request.approval_id).status is ApprovalStatus.TIMED_OUT
    with pytest.raises(ApprovalTimedOutError):
        service.claim_execution(request.approval_id, "admin-agent")
    events = {event.event_type for event in audit.list_events(approval_id=request.approval_id)}
    assert {"APPROVAL_TIMED_OUT", "APPROVAL_FINAL_DENY"} <= events


def test_break_glass_is_role_reason_and_ttl_bound() -> None:
    service, audit, clock = _service()
    disabled = _approval(service, "default-high-risk-workflow")
    with pytest.raises(ApprovalDeniedError):
        service.break_glass(disabled.approval_id, SECURITY_LEAD, "Production outage is causing a serious customer impact.")
    request = _approval(service)
    with pytest.raises(ApprovalDeniedError):
        service.break_glass(request.approval_id, SECURITY_ADMIN, "Production outage is causing a serious customer impact.")
    with pytest.raises(ApprovalDeniedError):
        service.break_glass(request.approval_id, SECURITY_LEAD, "urgent")
    granted = service.break_glass(request.approval_id, SECURITY_LEAD, "Production outage is causing a serious customer impact.")
    assert granted.status is ApprovalStatus.BREAK_GLASS_APPROVED
    service.claim_execution(request.approval_id, "admin-agent")
    assert service.complete_execution(request.approval_id, True, "admin-agent").status is ApprovalStatus.EXECUTED
    with pytest.raises(ApprovalAlreadyConsumedError):
        service.claim_execution(request.approval_id, "admin-agent")
    expiring = _approval(service)
    service.break_glass(expiring.approval_id, SECURITY_LEAD, "Production outage is causing a serious customer impact.")
    clock.advance(301)
    assert service.get(expiring.approval_id).status is ApprovalStatus.EXPIRED
    with pytest.raises(ApprovalExpiredError):
        service.claim_execution(expiring.approval_id, "admin-agent")
    events = {event.event_type for event in audit.list_events(approval_id=expiring.approval_id)}
    assert {"BREAK_GLASS_REQUESTED", "BREAK_GLASS_GRANTED", "BREAK_GLASS_EXPIRED"} <= events
