"""Official-SDK Streamable-HTTP client for configured downstream MCP servers."""

from typing import Any, Protocol

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp_types import CallToolResult, Tool

from app.gateway.servers import DownstreamServerRegistry


class DownstreamUnavailableError(RuntimeError):
    """A downstream MCP server could not be reached safely."""


class DownstreamTimeoutError(DownstreamUnavailableError):
    """A downstream MCP server exceeded the configured deadline."""


class DownstreamMCPClient(Protocol):
    async def list_tools(self, server_id: str) -> list[Tool]: ...

    async def call_tool(
        self, server_id: str, tool_name: str, arguments: dict[str, Any]
    ) -> CallToolResult: ...


class MCPDownstreamClient:
    """One-request-at-a-time downstream client with no automatic retries."""

    def __init__(self, servers: DownstreamServerRegistry, timeout_seconds: float) -> None:
        self._servers = servers
        self._timeout_seconds = timeout_seconds

    async def list_tools(self, server_id: str) -> list[Tool]:
        async def request(session: ClientSession) -> list[Tool]:
            return (await session.list_tools()).tools

        return await self._request(server_id, request)

    async def call_tool(
        self, server_id: str, tool_name: str, arguments: dict[str, Any]
    ) -> CallToolResult:
        async def request(session: ClientSession) -> CallToolResult:
            result = await session.call_tool(tool_name, arguments)
            if not isinstance(result, CallToolResult):
                raise DownstreamUnavailableError("Downstream returned an unsupported tool response.")
            return result

        return await self._request(server_id, request)

    async def _request(self, server_id: str, operation: Any) -> Any:
        server = self._servers.get(server_id)
        if server is None or not server.enabled:
            raise DownstreamUnavailableError("Configured downstream server is unavailable.")
        try:
            async with httpx2.AsyncClient(timeout=self._timeout_seconds) as http_client:
                async with streamable_http_client(str(server.url), http_client=http_client) as streams:
                    read_stream, write_stream = streams
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()
                        return await operation(session)
        except httpx2.TimeoutException as error:
            raise DownstreamTimeoutError("Downstream MCP server timed out.") from error
        except DownstreamUnavailableError:
            raise
        except Exception as error:
            raise DownstreamUnavailableError("Downstream MCP server is unavailable.") from error
