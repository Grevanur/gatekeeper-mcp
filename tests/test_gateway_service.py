import asyncio
import json
from typing import Any

from mcp_types import CallToolResult, TextContent, Tool

from app.auth.identity import AgentIdentity, load_agents_configuration
from app.auth.permissions import PermissionEvaluator
from app.gateway.downstream import DownstreamTimeoutError, DownstreamUnavailableError
from app.gateway.errors import GatewayErrorCode
from app.gateway.metadata import ToolMetadataRegistry
from app.gateway.servers import DownstreamServerRegistry
from app.gateway.service import MCPGatewayService
from app.security.evaluator import SecurityEvaluator


class FakeDownstreamClient:
    def __init__(self, tools_by_server: dict[str, list[Tool]]) -> None:
        self.tools_by_server = tools_by_server
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.fail_list = False
        self.fail_call = False

    async def list_tools(self, server_id: str) -> list[Tool]:
        if self.fail_list:
            raise DownstreamUnavailableError("offline")
        return self.tools_by_server.get(server_id, [])

    async def call_tool(
        self, server_id: str, tool_name: str, arguments: dict[str, Any]
    ) -> CallToolResult:
        if self.fail_call:
            raise DownstreamTimeoutError("timed out")
        self.calls.append((server_id, tool_name, arguments))
        return CallToolResult(content=[TextContent(text="downstream result")])


def _tool(name: str) -> Tool:
    return Tool(name=name, description=f"{name} description", inputSchema={"type": "object"})


def _service(fake_client: FakeDownstreamClient) -> MCPGatewayService:
    agents = load_agents_configuration("config/agents.yaml")
    return MCPGatewayService(
        servers=DownstreamServerRegistry.from_config_file("config/mcp_servers.yaml"),
        metadata=ToolMetadataRegistry.from_config_file("config/tool_metadata.yaml"),
        permissions=PermissionEvaluator(agents),
        security_evaluator=SecurityEvaluator.from_config_directory("config"),
        downstream_client=fake_client,  # type: ignore[arg-type]
    )


def _agent(agent_id: str, role: str = "support", environment: str = "development") -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id,
        owner="demo-user",
        role=role,
        environment=environment,
    )


def _error_code(result: CallToolResult) -> str:
    return json.loads(result.content[0].text)["security"]["code"]


def test_list_tools_namespaces_allowed_tools_and_preserves_metadata() -> None:
    fake = FakeDownstreamClient(
        {
            "normal-tools": [_tool("tickets.search"), _tool("knowledge.search")],
            "sensitive-data": [_tool("customer.read"), _tool("secrets.read")],
            "messaging": [_tool("tickets.search"), _tool("external.send")],
        }
    )

    tools = asyncio.run(_service(fake).list_tools(_agent("support-agent")))

    assert [tool.name for tool in tools] == [
        "normal-tools.tickets.search",
        "normal-tools.knowledge.search",
        "sensitive-data.customer.read",
    ]
    assert tools[0].description == "tickets.search description"
    assert tools[0].input_schema == {"type": "object"}


def test_allowed_call_forwards_original_tool_name_once() -> None:
    fake = FakeDownstreamClient({"normal-tools": [_tool("tickets.search")]})

    outcome = asyncio.run(
        _service(fake).call_tool(
            _agent("support-agent"),
            "normal-tools.tickets.search",
            {"query": "login"},
            "session-1",
        )
    )

    assert outcome.error is None
    assert outcome.result.is_error is False
    assert fake.calls == [("normal-tools", "tickets.search", {"query": "login"})]


def test_permission_denied_call_never_reaches_downstream() -> None:
    fake = FakeDownstreamClient({"sensitive-data": [_tool("secrets.read")]})

    outcome = asyncio.run(
        _service(fake).call_tool(
            _agent("support-agent"),
            "sensitive-data.secrets.read",
            {},
            "session-1",
        )
    )

    assert outcome.error is not None
    assert outcome.error.code is GatewayErrorCode.PERMISSION_DENIED
    assert fake.calls == []


def test_external_send_without_sensitive_session_requires_approval() -> None:
    fake = FakeDownstreamClient({"messaging": [_tool("external.send")]})

    outcome = asyncio.run(
        _service(fake).call_tool(
            _agent("admin-agent", role="admin"),
            "messaging.external.send",
            {"destination": "external@example.local", "data": "classified"},
            "session-1",
        )
    )

    assert outcome.error is not None
    assert outcome.error.code is GatewayErrorCode.APPROVAL_REQUIRED
    assert fake.calls == []


def test_approval_required_call_never_reaches_downstream() -> None:
    fake = FakeDownstreamClient({"sensitive-data": [_tool("database.delete")]})

    outcome = asyncio.run(
        _service(fake).call_tool(
            _agent("admin-agent", role="admin", environment="production"),
            "sensitive-data.database.delete",
            {"table": "customers"},
            "session-1",
        )
    )

    assert outcome.error is not None
    assert outcome.error.code is GatewayErrorCode.APPROVAL_REQUIRED
    assert fake.calls == []


def test_unknown_server_unknown_tool_and_downstream_failure_are_controlled() -> None:
    fake = FakeDownstreamClient({"normal-tools": [_tool("tickets.search")]})
    service = _service(fake)

    unknown_server = asyncio.run(
        service.call_tool(_agent("support-agent"), "missing.tickets.search", {}, "session-1")
    )
    unknown_tool = asyncio.run(
        service.call_tool(_agent("support-agent"), "normal-tools.unconfigured.tool", {}, "session-1")
    )
    fake.fail_list = True
    unavailable = asyncio.run(
        service.call_tool(_agent("support-agent"), "normal-tools.tickets.search", {}, "session-1")
    )

    assert _error_code(unknown_server.result) == "UNKNOWN_SERVER"
    assert _error_code(unknown_tool.result) == "UNKNOWN_TOOL"
    assert _error_code(unavailable.result) == "DOWNSTREAM_UNAVAILABLE"
    assert fake.calls == []
