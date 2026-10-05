"""SQLAlchemy persistence models for audit, approval, and session state."""

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for gateway persistence models."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditEventRecord(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    session_id: Mapped[str | None] = mapped_column(String(128), index=True)
    agent_id: Mapped[str | None] = mapped_column(String(128), index=True)
    agent_role: Mapped[str | None] = mapped_column(String(64))
    environment: Mapped[str | None] = mapped_column(String(64))
    gateway_tool_name: Mapped[str | None] = mapped_column(String(256), index=True)
    downstream_server: Mapped[str | None] = mapped_column(String(128))
    downstream_tool_name: Mapped[str | None] = mapped_column(String(128))
    sanitized_arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    permission_allowed: Mapped[bool | None] = mapped_column(Boolean)
    permission_reason: Mapped[str | None] = mapped_column(Text)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    risk_level: Mapped[str | None] = mapped_column(String(32), index=True)
    risk_factors: Mapped[list] = mapped_column(JSON, default=list)
    matched_policy: Mapped[str | None] = mapped_column(String(128))
    policy_action: Mapped[str | None] = mapped_column(String(32))
    decision_reason: Mapped[str | None] = mapped_column(Text)
    final_decision: Mapped[str | None] = mapped_column(String(32), index=True)
    approval_id: Mapped[str | None] = mapped_column(String(64), index=True)
    approval_status: Mapped[str | None] = mapped_column(String(32))
    execution_status: Mapped[str | None] = mapped_column(String(32))
    downstream_status: Mapped[str | None] = mapped_column(String(64))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)


class ApprovalRequestRecord(Base):
    __tablename__ = "approval_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    approval_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    session_id: Mapped[str] = mapped_column(String(128), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    gateway_tool_name: Mapped[str] = mapped_column(String(256))
    downstream_server: Mapped[str] = mapped_column(String(128))
    downstream_tool_name: Mapped[str] = mapped_column(String(128))
    sanitized_arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    original_arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    argument_hash: Mapped[str] = mapped_column(String(64))
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(32))
    risk_factors: Mapped[list] = mapped_column(JSON, default=list)
    matched_policy: Mapped[str | None] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), index=True, default="PENDING")
    approved_by: Mapped[str | None] = mapped_column(String(128))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    denied_by: Mapped[str | None] = mapped_column(String(128))
    denied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_status: Mapped[str] = mapped_column(String(32), default="PENDING_APPROVAL")
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SessionSecurityContextRecord(Base):
    __tablename__ = "session_security_contexts"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    sensitive_data_accessed: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitive_categories: Mapped[list] = mapped_column(JSON, default=list)
    tools_called: Mapped[list] = mapped_column(JSON, default=list)
    external_actions_attempted: Mapped[int] = mapped_column(Integer, default=0)
    recent_risk_scores: Mapped[list] = mapped_column(JSON, default=list)
    last_sensitive_access_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
