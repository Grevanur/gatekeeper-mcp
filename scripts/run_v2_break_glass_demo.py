"""Show exceptional, reason-bound, short-lived break-glass authorization."""

from app.approvals.identity import ApproverIdentity
from run_v2_approval_escalation_demo import make_service, request


if __name__ == "__main__":
    service, _ = make_service()
    pending = request(service)
    lead = ApproverIdentity(subject_id="security-lead-1", display_name="Security Lead", role="security_lead")
    granted = service.break_glass(
        pending.approval_id, lead, "Production outage is causing a serious customer impact."
    )
    service.claim_execution(pending.approval_id, "admin-agent")
    executed = service.complete_execution(pending.approval_id, True, "admin-agent")
    print("GATEKEEPER MCP — BREAK-GLASS")
    print("Status:", granted.status.value)
    print("Reason-bound emergency approval: GRANTED")
    print("One-time execution:", executed.status.value)
    print("Auditability: BREAK_GLASS_REQUESTED, BREAK_GLASS_GRANTED, BREAK_GLASS_EXECUTED")
