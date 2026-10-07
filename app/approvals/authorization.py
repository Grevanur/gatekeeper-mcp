"""Role-bound approval authority checks."""

from pydantic import BaseModel

from app.approvals.identity import ApproverIdentity
from app.approvals.workflows import ApprovalWorkflow


class ApprovalAuthority(BaseModel):
    allowed: bool
    reason: str


def can_approve(
    approver: ApproverIdentity, requesting_agent_id: str, workflow: ApprovalWorkflow, stage: str
) -> ApprovalAuthority:
    if approver.subject_id == requesting_agent_id:
        return ApprovalAuthority(allowed=False, reason="Requesting agent cannot approve its own action.")
    allowed_roles = workflow.primary.roles if stage == "PRIMARY" else (workflow.fallback.roles if workflow.fallback else [])
    if approver.role not in allowed_roles:
        return ApprovalAuthority(
            allowed=False,
            reason="Approver role is not authorized for the current approval stage.",
        )
    return ApprovalAuthority(allowed=True, reason="Approver role is authorized.")
