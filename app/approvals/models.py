"""Safe approval-governance API models and explicit lifecycle states."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel

from app.approvals.workflows import ApprovalWorkflow
from app.database.models import ApprovalRequestRecord


class ApprovalStatus(str, Enum):
    PENDING_PRIMARY = "PENDING_PRIMARY"
    PENDING_FALLBACK = "PENDING_FALLBACK"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    TIMED_OUT = "TIMED_OUT"
    BREAK_GLASS_APPROVED = "BREAK_GLASS_APPROVED"
    EXPIRED = "EXPIRED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class BreakGlassDetails(BaseModel):
    enabled: bool
    allowed_roles: list[str]
    expires_at: datetime | None


class ApprovalRequest(BaseModel):
    approval_id: str
    created_at: datetime
    expires_at: datetime
    request_id: str
    session_id: str
    agent_id: str
    gateway_tool_name: str
    downstream_server: str
    downstream_tool_name: str
    sanitized_arguments: dict[str, Any]
    argument_hash: str
    risk_score: int
    risk_level: str
    risk_factors: list[dict[str, Any]]
    matched_policy: str | None
    reason: str
    status: ApprovalStatus
    workflow_id: str
    stage: str
    authorized_roles: list[str]
    current_stage_expires_at: datetime | None
    primary_expires_at: datetime | None
    fallback_started_at: datetime | None
    fallback_expires_at: datetime | None
    break_glass: BreakGlassDetails
    approved_by: str | None
    approved_at: datetime | None
    denied_by: str | None
    denied_at: datetime | None
    execution_status: str
    executed_at: datetime | None

    @classmethod
    def from_record(cls, record: ApprovalRequestRecord, workflow_id: str, workflow: ApprovalWorkflow) -> "ApprovalRequest":
        status = ApprovalStatus.PENDING_PRIMARY if record.status == "PENDING" else ApprovalStatus(record.status)
        roles = workflow.primary.roles if record.stage == "PRIMARY" else (workflow.fallback.roles if record.stage == "FALLBACK" and workflow.fallback else [])
        current_deadline = record.primary_expires_at if record.stage == "PRIMARY" else (record.fallback_expires_at if record.stage == "FALLBACK" else record.break_glass_expires_at)
        return cls(
            approval_id=record.approval_id, created_at=record.created_at, expires_at=record.expires_at,
            request_id=record.request_id, session_id=record.session_id, agent_id=record.agent_id,
            gateway_tool_name=record.gateway_tool_name, downstream_server=record.downstream_server,
            downstream_tool_name=record.downstream_tool_name, sanitized_arguments=record.sanitized_arguments or {},
            argument_hash=record.argument_hash, risk_score=record.risk_score, risk_level=record.risk_level,
            risk_factors=record.risk_factors or [], matched_policy=record.matched_policy, reason=record.reason,
            status=status, workflow_id=workflow_id, stage=record.stage, authorized_roles=roles,
            current_stage_expires_at=current_deadline, primary_expires_at=record.primary_expires_at,
            fallback_started_at=record.fallback_started_at, fallback_expires_at=record.fallback_expires_at,
            break_glass=BreakGlassDetails(enabled=workflow.break_glass.enabled, allowed_roles=workflow.break_glass.roles, expires_at=record.break_glass_expires_at),
            approved_by=record.approved_by, approved_at=record.approved_at, denied_by=record.denied_by,
            denied_at=record.denied_at, execution_status=record.execution_status, executed_at=record.executed_at,
        )


class ExecutionClaim(BaseModel):
    approval: ApprovalRequest
    original_arguments: dict[str, Any]
