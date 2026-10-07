"""Append-only persistence and retrieval for gateway audit events."""

from collections.abc import Callable
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.models import AuditEvent
from app.audit.redaction import sanitize_arguments
from app.database.models import AuditEventRecord


class AuditService:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def record(
        self,
        event_type: str,
        *,
        arguments: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        **fields: Any,
    ) -> AuditEvent:
        """Persist one immutable security timeline event."""

        record = AuditEventRecord(
            event_id=f"evt_{uuid4().hex}",
            event_type=event_type,
            sanitized_arguments=sanitize_arguments(arguments or {}),
            governance_metadata=sanitize_arguments(metadata or {}),
            **fields,
        )
        with self._session_factory() as session:
            session.add(record)
            session.commit()
            session.refresh(record)
            return AuditEvent.from_record(record)

    def get_event(self, event_id: str) -> AuditEvent | None:
        with self._session_factory() as session:
            record = session.scalar(select(AuditEventRecord).where(AuditEventRecord.event_id == event_id))
            return AuditEvent.from_record(record) if record else None

    def list_events(
        self,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
        decision: str | None = None,
        risk_level: str | None = None,
        tool: str | None = None,
        approval_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        statement = select(AuditEventRecord).order_by(AuditEventRecord.timestamp.desc(), AuditEventRecord.id.desc())
        if agent_id is not None:
            statement = statement.where(AuditEventRecord.agent_id == agent_id)
        if session_id is not None:
            statement = statement.where(AuditEventRecord.session_id == session_id)
        if decision is not None:
            statement = statement.where(AuditEventRecord.final_decision == decision)
        if risk_level is not None:
            statement = statement.where(AuditEventRecord.risk_level == risk_level)
        if tool is not None:
            statement = statement.where(AuditEventRecord.gateway_tool_name == tool)
        if approval_id is not None:
            statement = statement.where(AuditEventRecord.approval_id == approval_id)
        safe_limit = min(max(limit, 1), 500)
        safe_offset = max(offset, 0)
        with self._session_factory() as session:
            records = session.scalars(statement.limit(safe_limit).offset(safe_offset)).all()
            return [AuditEvent.from_record(record) for record in records]
