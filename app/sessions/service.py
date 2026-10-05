"""Persistence service for agent-owned, minimal session security context."""

from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import SessionSecurityContextRecord
from app.sessions.models import SessionSecurityContext


class SessionNotFoundError(LookupError):
    pass


class SessionOwnershipMismatchError(PermissionError):
    pass


class SessionSecurityService:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def get_or_create(self, session_id: str, agent_id: str) -> SessionSecurityContext:
        with self._session_factory() as session:
            record = self._get_record(session, session_id)
            if record is None:
                record = SessionSecurityContextRecord(session_id=session_id, agent_id=agent_id)
                session.add(record)
                session.commit()
                session.refresh(record)
            self._require_owner(record, agent_id)
            return SessionSecurityContext.from_record(record)

    def get(self, session_id: str, agent_id: str) -> SessionSecurityContext:
        with self._session_factory() as session:
            record = self._get_record(session, session_id)
            if record is None:
                raise SessionNotFoundError(session_id)
            self._require_owner(record, agent_id)
            return SessionSecurityContext.from_record(record)

    def record_evaluation(
        self,
        session_id: str,
        agent_id: str,
        gateway_tool_name: str,
        risk_score: int,
        is_external_action: bool,
    ) -> SessionSecurityContext:
        with self._session_factory() as session:
            record = self._require_existing_or_create(session, session_id, agent_id)
            record.tools_called = (record.tools_called or [])[-99:] + [gateway_tool_name]
            record.recent_risk_scores = (record.recent_risk_scores or [])[-19:] + [risk_score]
            if is_external_action:
                record.external_actions_attempted += 1
            session.commit()
            session.refresh(record)
            return SessionSecurityContext.from_record(record)

    def mark_sensitive_access(
        self,
        session_id: str,
        agent_id: str,
        categories: list[str],
    ) -> SessionSecurityContext:
        with self._session_factory() as session:
            record = self._require_existing_or_create(session, session_id, agent_id)
            record.sensitive_data_accessed = True
            record.sensitive_categories = list(dict.fromkeys((record.sensitive_categories or []) + categories))
            record.last_sensitive_access_at = datetime.now(timezone.utc)
            session.commit()
            session.refresh(record)
            return SessionSecurityContext.from_record(record)

    @staticmethod
    def _get_record(session: Session, session_id: str) -> SessionSecurityContextRecord | None:
        return session.scalar(
            select(SessionSecurityContextRecord).where(SessionSecurityContextRecord.session_id == session_id)
        )

    def _require_existing_or_create(
        self, session: Session, session_id: str, agent_id: str
    ) -> SessionSecurityContextRecord:
        record = self._get_record(session, session_id)
        if record is None:
            record = SessionSecurityContextRecord(session_id=session_id, agent_id=agent_id)
            session.add(record)
            session.flush()
        self._require_owner(record, agent_id)
        return record

    @staticmethod
    def _require_owner(record: SessionSecurityContextRecord, agent_id: str) -> None:
        if record.agent_id != agent_id:
            raise SessionOwnershipMismatchError(record.session_id)
