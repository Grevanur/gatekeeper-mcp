"""Safe API representations of immutable audit events."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.database.models import AuditEventRecord


class AuditEvent(BaseModel):
    event_id: str
    event_type: str
    timestamp: datetime
    request_id: str | None
    session_id: str | None
    agent_id: str | None
    agent_role: str | None
    environment: str | None
    gateway_tool_name: str | None
    downstream_server: str | None
    downstream_tool_name: str | None
    sanitized_arguments: dict[str, Any]
    permission_allowed: bool | None
    permission_reason: str | None
    risk_score: int | None
    risk_level: str | None
    risk_factors: list[dict[str, Any]]
    matched_policy: str | None
    policy_action: str | None
    decision_reason: str | None
    final_decision: str | None
    approval_id: str | None
    approval_status: str | None
    execution_status: str | None
    downstream_status: str | None
    latency_ms: int | None
    error_code: str | None
    error_message: str | None

    @classmethod
    def from_record(cls, record: AuditEventRecord) -> "AuditEvent":
        return cls(
            event_id=record.event_id,
            event_type=record.event_type,
            timestamp=record.timestamp,
            request_id=record.request_id,
            session_id=record.session_id,
            agent_id=record.agent_id,
            agent_role=record.agent_role,
            environment=record.environment,
            gateway_tool_name=record.gateway_tool_name,
            downstream_server=record.downstream_server,
            downstream_tool_name=record.downstream_tool_name,
            sanitized_arguments=record.sanitized_arguments or {},
            permission_allowed=record.permission_allowed,
            permission_reason=record.permission_reason,
            risk_score=record.risk_score,
            risk_level=record.risk_level,
            risk_factors=record.risk_factors or [],
            matched_policy=record.matched_policy,
            policy_action=record.policy_action,
            decision_reason=record.decision_reason,
            final_decision=record.final_decision,
            approval_id=record.approval_id,
            approval_status=record.approval_status,
            execution_status=record.execution_status,
            downstream_status=record.downstream_status,
            latency_ms=record.latency_ms,
            error_code=record.error_code,
            error_message=record.error_message,
        )
