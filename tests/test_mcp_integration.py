"""Real Streamable-HTTP MCP client -> gateway -> downstream integration test."""

import asyncio
import socket
import threading
import time

import httpx2
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer

from app.auth.identity import load_agents_configuration
from app.auth.permissions import PermissionEvaluator
from app.gateway.downstream import MCPDownstreamClient
from app.gateway.mcp_server import create_gateway_mcp_server
from app.gateway.metadata import ToolMetadataConfiguration, ToolMetadataRegistry
from app.gateway.servers import MCPServersConfiguration, DownstreamServerRegistry
from app.gateway.service import MCPGatewayService
from app.security.evaluator import SecurityEvaluator


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _start_server(app: object, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started
    return server, thread


def test_real_mcp_gateway_forwards_allowed_call_and_blocks_forbidden_call() -> None:
    execution_count = {"tickets.search": 0, "secrets.read": 0}
    downstream = MCPServer("integration-downstream")

    @downstream.tool(name="tickets.search")
    def tickets_search(query: str) -> dict[str, str]:
        execution_count["tickets.search"] += 1
        return {"query": query, "status": "found"}

    @downstream.tool(name="secrets.read")
    def secrets_read() -> dict[str, str]:
        execution_count["secrets.read"] += 1
        return {"secret": "never returned to support agent"}

    downstream_port = _free_port()
    gateway_port = _free_port()
    servers = DownstreamServerRegistry(
        MCPServersConfiguration.model_validate(
            {
                "mcp_servers": {
                    "normal-tools": {
                        "url": f"http://127.0.0.1:{downstream_port}/mcp",
                        "enabled": True,
                    },
                    "sensitive-data": {
                        "url": f"http://127.0.0.1:{downstream_port}/mcp",
                        "enabled": True,
                    },
                }
            }
        )
    )
    metadata = ToolMetadataRegistry(
        ToolMetadataConfiguration.model_validate(
            {
                "tools": {
                    "normal-tools.tickets.search": {
                        "risk_category": "low",
                        "data_classification": "internal",
                    },
                    "sensitive-data.secrets.read": {
                        "risk_category": "high",
                        "data_classification": "secret",
                    },
                }
            }
        )
    )
    agents = load_agents_configuration("config/agents.yaml")
    service = MCPGatewayService(
        servers=servers,
        metadata=metadata,
        permissions=PermissionEvaluator(agents),
        security_evaluator=SecurityEvaluator.from_config_directory("config"),
        downstream_client=MCPDownstreamClient(servers, timeout_seconds=2),
    )
    gateway = create_gateway_mcp_server(lambda: service)

    downstream_process, downstream_thread = _start_server(
        downstream.streamable_http_app(), downstream_port
    )
    gateway_process, gateway_thread = _start_server(gateway.streamable_http_app(), gateway_port)
    try:
        async def exercise_gateway() -> None:
            async with httpx2.AsyncClient(
                headers={"Authorization": "Bearer dev-support-token"}
            ) as http_client:
                async with streamable_http_client(
                    f"http://127.0.0.1:{gateway_port}/mcp", http_client=http_client
                ) as streams:
                    read_stream, write_stream = streams
                    async with ClientSession(read_stream, write_stream) as client:
                        await client.initialize()
                        discovered = await client.list_tools()
                        assert [tool.name for tool in discovered.tools] == ["normal-tools.tickets.search"]

                        allowed = await client.call_tool("normal-tools.tickets.search", {"query": "login"})
                        denied = await client.call_tool("sensitive-data.secrets.read", {})

                        assert allowed.is_error is False
                        assert denied.is_error is True

        asyncio.run(exercise_gateway())
        assert execution_count == {"tickets.search": 1, "secrets.read": 0}
    finally:
        gateway_process.should_exit = True
        downstream_process.should_exit = True
        gateway_thread.join(timeout=5)
        downstream_thread.join(timeout=5)
