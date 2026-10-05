"""Safe approval API models and lifecycle states."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel

from app.database.models import ApprovalRequestRecord


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


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
    approved_by: str | None
    approved_at: datetime | None
    denied_by: str | None
    denied_at: datetime | None
    execution_status: str
    executed_at: datetime | None

    @classmethod
    def from_record(cls, record: ApprovalRequestRecord) -> "ApprovalRequest":
        return cls(
            approval_id=record.approval_id,
            created_at=record.created_at,
            expires_at=record.expires_at,
            request_id=record.request_id,
            session_id=record.session_id,
            agent_id=record.agent_id,
            gateway_tool_name=record.gateway_tool_name,
            downstream_server=record.downstream_server,
            downstream_tool_name=record.downstream_tool_name,
            sanitized_arguments=record.sanitized_arguments or {},
            argument_hash=record.argument_hash,
            risk_score=record.risk_score,
            risk_level=record.risk_level,
            risk_factors=record.risk_factors or [],
            matched_policy=record.matched_policy,
            reason=record.reason,
            status=ApprovalStatus(record.status),
            approved_by=record.approved_by,
            approved_at=record.approved_at,
            denied_by=record.denied_by,
            denied_at=record.denied_at,
            execution_status=record.execution_status,
            executed_at=record.executed_at,
        )


class ExecutionClaim(BaseModel):
    approval: ApprovalRequest
    original_arguments: dict[str, Any]
