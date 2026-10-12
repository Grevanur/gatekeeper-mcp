"""In-memory downstream spy used by security evaluations and regression tests."""

from dataclasses import dataclass, field
from time import time
from typing import Any

from mcp_types import CallToolResult, TextContent, Tool

from app.gateway.downstream import DownstreamTimeoutError, DownstreamUnavailableError


@dataclass(frozen=True)
class ExecutionRecord:
    server_id: str
    tool_name: str
    arguments: dict[str, Any]
    timestamp: float
    request_id: str | None = None


@dataclass
class DownstreamExecutionSpy:
    """A deterministic downstream double that records only real forwarded calls."""

    tools_by_server: dict[str, list[Tool]]
    records: list[ExecutionRecord] = field(default_factory=list)
    unavailable: bool = False
    timeout: bool = False

    @property
    def call_count(self) -> int:
        return len(self.records)

    async def list_tools(self, server_id: str) -> list[Tool]:
        if self.unavailable:
            raise DownstreamUnavailableError("evaluation downstream unavailable")
        return self.tools_by_server.get(server_id, [])

    async def call_tool(
        self, server_id: str, tool_name: str, arguments: dict[str, Any]
    ) -> CallToolResult:
        if self.timeout:
            raise DownstreamTimeoutError("evaluation downstream timed out")
        if self.unavailable:
            raise DownstreamUnavailableError("evaluation downstream unavailable")
        self.records.append(ExecutionRecord(server_id, tool_name, dict(arguments), time()))
        return CallToolResult(content=[TextContent(text="evaluation downstream result")])


def tool(name: str) -> Tool:
    return Tool(name=name, description=f"Evaluation tool {name}", inputSchema={"type": "object"})
