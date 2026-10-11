"""Demonstrate exact binding without invoking a downstream MCP server."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.approvals.binding import ApprovalBinding
from app.approvals.identity import ApproverIdentity
from app.approvals.service import ApprovalBindingMismatchError, ApprovalService
from app.approvals.workflows import ApprovalWorkflowRegistry
from app.database.models import Base


def binding(destination: str) -> ApprovalBinding:
    return ApprovalBinding.create(
        agent_id="admin-agent", session_id="binding-demo", gateway_tool_name="messaging.external.send",
        downstream_server="messaging", downstream_tool_name="external.send",
        arguments={"destination": destination, "data": "incident-summary"},
        destination=destination, destination_type="email", environment="development",
        security_context={"risk_level": "HIGH", "is_external_destination": True},
        policy_id="high-risk-approval", policy_version=1,
    )


if __name__ == "__main__":
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    service = ApprovalService(sessionmaker(bind=engine), ApprovalWorkflowRegistry.from_config_file("config/approval_workflows.yaml"))
    original = binding("security@company.com")
    approval = service.create(
        request_id="binding-demo", session_id="binding-demo", agent_id="admin-agent",
        gateway_tool_name=original.gateway_tool_name, downstream_server="messaging",
        downstream_tool_name="external.send", arguments={"destination": "security@company.com", "data": "incident-summary"},
        risk_score=80, risk_level="HIGH", risk_factors=[], matched_policy="high-risk-needs-approval",
        workflow_id="default-high-risk-workflow", reason="Approval required.", binding=original,
        policy_id="high-risk-approval", policy_version=1,
    )
    service.approve(approval.approval_id, ApproverIdentity(subject_id="security-admin-1", display_name="Admin", role="security_admin"))
    print("GATEKEEPER MCP — EXACT APPROVAL BINDING")
    print("Attempt 1: exact action -> EXECUTED")
    service.claim_execution(approval.approval_id, "admin-agent", binding=original)
    service.complete_execution(approval.approval_id, True, "admin-agent")
    try:
        service.claim_execution(approval.approval_id, "admin-agent", binding=binding("external@gmail.com"))
    except ApprovalBindingMismatchError as error:
        print("Attempt 2: destination changed -> DENIED")
        print("Reason:", error.code)
        print("Fresh decision required: YES")
