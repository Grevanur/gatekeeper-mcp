from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.audit.service import AuditService
from app.database.models import Base


def _audit_service() -> AuditService:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return AuditService(sessionmaker(bind=engine))


def test_audit_events_are_redacted_and_filterable() -> None:
    service = _audit_service()
    denied = service.record(
        "TOOL_DECISION",
        arguments={"password": "not-stored", "query": "login"},
        agent_id="support-agent",
        session_id="session-1",
        gateway_tool_name="sensitive-data.secrets.read",
        final_decision="DENY",
        risk_level="CRITICAL",
        execution_status="BLOCKED",
    )
    service.record(
        "TOOL_DECISION",
        agent_id="admin-agent",
        session_id="session-2",
        gateway_tool_name="normal-tools.tickets.search",
        final_decision="ALLOW",
        risk_level="LOW",
        execution_status="EXECUTED",
    )

    assert denied.sanitized_arguments["password"] == "[REDACTED]"
    assert service.get_event(denied.event_id) is not None
    events = service.list_events(decision="DENY", risk_level="CRITICAL")
    assert [event.event_id for event in events] == [denied.event_id]
