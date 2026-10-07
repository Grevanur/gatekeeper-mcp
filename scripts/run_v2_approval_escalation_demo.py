"""Show fail-closed escalation and fallback approval without waiting in real time."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.approvals.identity import ApproverIdentity
from app.approvals.service import ApprovalService
from app.approvals.workflows import ApprovalWorkflowRegistry
from app.audit.service import AuditService
from app.database.models import Base


class DemoClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def make_service() -> tuple[ApprovalService, DemoClock]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    clock = DemoClock()
    return ApprovalService(factory, ApprovalWorkflowRegistry.from_config_file("config/approval_workflows.yaml"), AuditService(factory), clock), clock


def request(service: ApprovalService):
    return service.create(
        request_id="demo-request", session_id="demo-session", agent_id="admin-agent",
        gateway_tool_name="sensitive-data.database.delete", downstream_server="sensitive-data",
        downstream_tool_name="database.delete", arguments={"table": "temporary_records"},
        risk_score=100, risk_level="CRITICAL", risk_factors=[],
        matched_policy="production-delete-requires-approval",
        workflow_id="production-destructive-workflow", reason="Production destructive operation.",
    )


if __name__ == "__main__":
    service, clock = make_service()
    pending = request(service)
    print("GATEKEEPER MCP — APPROVAL ESCALATION")
    print("Request: production.database.delete")
    print("Decision: REQUIRE_APPROVAL")
    print("Primary approver: system_owner")
    clock.advance(901)
    print("Primary approver: NO RESPONSE")
    print("State:", service.get(pending.approval_id).status.value)
    clock.advance(901)
    final = service.get(pending.approval_id)
    print("Fallback approver: NO RESPONSE")
    print("Final state:", final.status.value)
    print("Reason: Approval workflow exhausted without authorization.")
    print("Downstream execution: NOT PERFORMED")

    fallback = request(service)
    clock.value = fallback.created_at + timedelta(seconds=901)
    service.get(fallback.approval_id)
    reviewer = ApproverIdentity(subject_id="security-admin-1", display_name="Security Admin", role="security_admin")
    service.approve(fallback.approval_id, reviewer)
    service.claim_execution(fallback.approval_id, "admin-agent")
    service.complete_execution(fallback.approval_id, True, "admin-agent")
    print("Fallback approval: EXECUTED ONCE")
