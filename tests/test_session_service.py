import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.models import Base
from app.sessions.service import SessionOwnershipMismatchError, SessionSecurityService


def _service() -> SessionSecurityService:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return SessionSecurityService(sessionmaker(bind=engine))


def test_session_tracks_sensitive_state_and_evaluation_history() -> None:
    service = _service()
    service.get_or_create("session-1", "support-agent")
    service.record_evaluation("session-1", "support-agent", "normal-tools.tickets.search", 5, False)
    sensitive = service.mark_sensitive_access("session-1", "support-agent", ["customer_data"])
    updated = service.record_evaluation(
        "session-1", "support-agent", "messaging.external.send", 100, True
    )

    assert sensitive.sensitive_data_accessed is True
    assert updated.sensitive_categories == ["customer_data"]
    assert updated.tools_called == ["normal-tools.tickets.search", "messaging.external.send"]
    assert updated.external_actions_attempted == 1


def test_session_cannot_be_reused_by_another_agent() -> None:
    service = _service()
    service.get_or_create("session-1", "support-agent")

    with pytest.raises(SessionOwnershipMismatchError):
        service.get("session-1", "admin-agent")
