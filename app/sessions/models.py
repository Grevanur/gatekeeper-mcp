"""Safe representations of persistent session security state."""

from datetime import datetime

from pydantic import BaseModel

from app.database.models import SessionSecurityContextRecord


class SessionSecurityContext(BaseModel):
    session_id: str
    agent_id: str
    created_at: datetime
    updated_at: datetime
    sensitive_data_accessed: bool
    sensitive_categories: list[str]
    tools_called: list[str]
    external_actions_attempted: int
    recent_risk_scores: list[int]
    last_sensitive_access_at: datetime | None

    @classmethod
    def from_record(cls, record: SessionSecurityContextRecord) -> "SessionSecurityContext":
        return cls(
            session_id=record.session_id,
            agent_id=record.agent_id,
            created_at=record.created_at,
            updated_at=record.updated_at,
            sensitive_data_accessed=record.sensitive_data_accessed,
            sensitive_categories=record.sensitive_categories or [],
            tools_called=record.tools_called or [],
            external_actions_attempted=record.external_actions_attempted,
            recent_risk_scores=record.recent_risk_scores or [],
            last_sensitive_access_at=record.last_sensitive_access_at,
        )
