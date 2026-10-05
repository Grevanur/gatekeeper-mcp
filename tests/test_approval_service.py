import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.approvals.models import ApprovalStatus
from app.approvals.service import (
    ApprovalAlreadyConsumedError,
    ApprovalArgumentMismatchError,
    ApprovalDeniedError,
    ApprovalExpiredError,
    ApprovalService,
)
from app.database.models import Base


def _service(ttl_seconds: int = 300) -> ApprovalService:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return ApprovalService(sessionmaker(bind=engine), ttl_seconds)


def _approval(service: ApprovalService):
    return service.create(
        request_id="req-1",
        session_id="session-1",
        agent_id="admin-agent",
        gateway_tool_name="sensitive-data.database.delete",
        downstream_server="sensitive-data",
        downstream_tool_name="database.delete",
        arguments={"table": "temporary_records"},
        risk_score=100,
        risk_level="CRITICAL",
        risk_factors=[],
        matched_policy="high-risk-needs-approval",
        reason="Approval required.",
    )


def test_approval_is_bound_to_request_arguments_and_executes_once() -> None:
    service = _service()
    request = _approval(service)
    approved = service.approve(request.approval_id, "security-reviewer")
    claim = service.claim_execution(request.approval_id, "admin-agent", {"table": "temporary_records"})
    executed = service.complete_execution(request.approval_id, success=True)

    assert approved.status is ApprovalStatus.APPROVED
    assert claim.original_arguments == {"table": "temporary_records"}
    assert executed.status is ApprovalStatus.EXECUTED
    with pytest.raises(ApprovalAlreadyConsumedError):
        service.claim_execution(request.approval_id, "admin-agent")


def test_approval_rejects_wrong_agent_and_argument_hash() -> None:
    service = _service()
    request = _approval(service)
    service.approve(request.approval_id, "security-reviewer")

    with pytest.raises(ApprovalDeniedError):
        service.claim_execution(request.approval_id, "other-agent")
    with pytest.raises(ApprovalArgumentMismatchError):
        service.claim_execution(request.approval_id, "admin-agent", {"table": "customers"})


def test_requester_cannot_self_approve_and_expired_cannot_execute() -> None:
    service = _service(ttl_seconds=-1)
    request = _approval(service)

    with pytest.raises(ApprovalExpiredError):
        service.claim_execution(request.approval_id, "admin-agent")
    assert service.get(request.approval_id).status is ApprovalStatus.EXPIRED

    fresh_service = _service()
    fresh = _approval(fresh_service)
    with pytest.raises(ApprovalDeniedError):
        fresh_service.approve(fresh.approval_id, "admin-agent")


def test_pending_approval_can_be_denied_and_not_executed() -> None:
    service = _service()
    request = _approval(service)
    denied = service.deny(request.approval_id, "security-reviewer")

    assert denied.status is ApprovalStatus.DENIED
    with pytest.raises(ApprovalAlreadyConsumedError):
        service.claim_execution(request.approval_id, "admin-agent")
