"""Gateway orchestration: resolve, evaluate, and conditionally forward MCP calls."""

import json
import logging
from dataclasses import dataclass
from time import perf_counter
from typing import Any
from uuid import uuid4

from mcp_types import CallToolResult, TextContent, Tool

from app.auth.identity import AgentIdentity
from app.auth.permissions import PermissionEvaluator
from app.gateway.downstream import (
    DownstreamMCPClient,
    DownstreamTimeoutError,
    DownstreamUnavailableError,
)
from app.gateway.errors import GatewayError, GatewayErrorCode
from app.gateway.metadata import ToolMetadataRegistry
from app.gateway.router import InvalidGatewayToolName, build_gateway_tool_name, parse_gateway_tool_name
from app.gateway.servers import DownstreamServerRegistry
from app.policy.models import PolicyAction
from app.security.evaluator import SecurityEvaluator
from app.security.models import ToolRequestContext


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False


@dataclass(frozen=True)
class GatewayCallResult:
    result: CallToolResult
    error: GatewayError | None = None


class MCPGatewayService:
    def __init__(
        self,
        servers: DownstreamServerRegistry,
        metadata: ToolMetadataRegistry,
        permissions: PermissionEvaluator,
        security_evaluator: SecurityEvaluator,
        downstream_client: DownstreamMCPClient,
    ) -> None:
        self._servers = servers
        self._metadata = metadata
        self._permissions = permissions
        self._security_evaluator = security_evaluator
        self._downstream_client = downstream_client

    async def list_tools(self, agent: AgentIdentity) -> list[Tool]:
        """Discover only enabled, configured tools the agent may use."""

        visible_tools: list[Tool] = []
        for server_id in self._servers.enabled_servers():
            try:
                downstream_tools = await self._downstream_client.list_tools(server_id)
            except DownstreamUnavailableError:
                continue
            for downstream_tool in downstream_tools:
                gateway_name = build_gateway_tool_name(server_id, downstream_tool.name)
                if self._metadata.get(gateway_name) is None:
                    continue
                if not self._permissions.evaluate(agent.agent_id, downstream_tool.name).allowed:
                    continue
                visible_tools.append(downstream_tool.model_copy(update={"name": gateway_name}))
        return visible_tools

    def authenticate_agent(self, token: str) -> AgentIdentity | None:
        """Resolve a bearer token through the existing security-core authenticator."""

        return self._security_evaluator.identity_authenticator.authenticate(token)

    async def call_tool(
        self,
        agent: AgentIdentity,
        gateway_tool_name: str,
        arguments: dict[str, Any],
        session_id: str,
    ) -> GatewayCallResult:
        """Fail closed unless a configured downstream call receives ALLOW."""

        request_id = str(uuid4())
        try:
            route = parse_gateway_tool_name(gateway_tool_name)
        except InvalidGatewayToolName:
            return self._error(
                GatewayErrorCode.INVALID_TOOL_NAME,
                "Tool name must be a namespaced gateway tool.",
                request_id,
                gateway_tool_name,
            )

        server = self._servers.get(route.server_id)
        if server is None or not server.enabled:
            return self._error(
                GatewayErrorCode.UNKNOWN_SERVER,
                "The requested downstream server is unavailable.",
                request_id,
                gateway_tool_name,
            )
        metadata = self._metadata.get(gateway_tool_name)
        if metadata is None:
            return self._error(
                GatewayErrorCode.UNKNOWN_TOOL,
                "Tool metadata is unavailable; execution was denied.",
                request_id,
                gateway_tool_name,
            )
        try:
            available_tools = await self._downstream_client.list_tools(route.server_id)
        except DownstreamTimeoutError:
            return self._error(
                GatewayErrorCode.DOWNSTREAM_TIMEOUT,
                "The downstream MCP server timed out.",
                request_id,
                gateway_tool_name,
            )
        except DownstreamUnavailableError:
            return self._error(
                GatewayErrorCode.DOWNSTREAM_UNAVAILABLE,
                "The downstream MCP server is unavailable.",
                request_id,
                gateway_tool_name,
            )
        if route.downstream_tool_name not in {tool.name for tool in available_tools}:
            return self._error(
                GatewayErrorCode.UNKNOWN_TOOL,
                "The requested tool is not advertised by the downstream server.",
                request_id,
                gateway_tool_name,
            )

        context = ToolRequestContext(
            request_id=request_id,
            session_id=session_id,
            agent=agent,
            tool_name=route.downstream_tool_name,
            arguments=arguments,
            data_classification=metadata.data_classification,
            is_write_operation=metadata.write_operation,
            is_external_destination=metadata.external_destination,
            sensitive_data_involved=metadata.data_classification in {"confidential", "secret"},
        )
        logger.info(
            "MCP_TOOL_REQUEST request_id=%s session_id=%s agent=%s gateway_tool=%s downstream_server=%s downstream_tool=%s",
            request_id,
            session_id,
            agent.agent_id,
            gateway_tool_name,
            route.server_id,
            route.downstream_tool_name,
        )
        try:
            evaluation = self._security_evaluator.evaluate(context)
        except Exception:
            return self._error(
                GatewayErrorCode.SECURITY_EVALUATION_FAILED,
                "Security evaluation failed; execution was denied.",
                request_id,
                gateway_tool_name,
            )

        if evaluation.final_decision is not PolicyAction.ALLOW:
            code = (
                GatewayErrorCode.APPROVAL_REQUIRED
                if evaluation.final_decision is PolicyAction.REQUIRE_APPROVAL
                else (
                    GatewayErrorCode.PERMISSION_DENIED
                    if not evaluation.permission.allowed
                    else GatewayErrorCode.POLICY_DENIED
                )
            )
            logger.info(
                "MCP_TOOL_BLOCKED request_id=%s decision=%s reason=%s",
                request_id,
                evaluation.final_decision.value,
                evaluation.reason,
            )
            return self._error(
                code,
                evaluation.reason,
                request_id,
                gateway_tool_name,
                decision=evaluation.final_decision.value,
                matched_policy=evaluation.policy.matched_policy if evaluation.policy else None,
                risk_score=evaluation.risk.score,
                risk_level=evaluation.risk.level.value,
            )

        started_at = perf_counter()
        try:
            downstream_result = await self._downstream_client.call_tool(
                route.server_id, route.downstream_tool_name, arguments
            )
        except DownstreamTimeoutError:
            return self._error(
                GatewayErrorCode.DOWNSTREAM_TIMEOUT,
                "The downstream MCP server timed out.",
                request_id,
                gateway_tool_name,
            )
        except DownstreamUnavailableError:
            return self._error(
                GatewayErrorCode.DOWNSTREAM_UNAVAILABLE,
                "The downstream MCP server is unavailable.",
                request_id,
                gateway_tool_name,
            )
        logger.info(
            "MCP_TOOL_RESULT request_id=%s status=SUCCESS latency_ms=%d",
            request_id,
            int((perf_counter() - started_at) * 1000),
        )
        return GatewayCallResult(result=downstream_result)

    @staticmethod
    def _error(
        code: GatewayErrorCode,
        message: str,
        request_id: str,
        tool_name: str,
        **details: Any,
    ) -> GatewayCallResult:
        error = GatewayError(
            code=code,
            message=message,
            request_id=request_id,
            tool_name=tool_name,
            **details,
        )
        return GatewayCallResult(
            result=CallToolResult(
                content=[TextContent(text=json.dumps({"security": error.model_dump(mode="json")}))],
                isError=True,
            ),
            error=error,
        )
