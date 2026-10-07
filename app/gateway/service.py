"""Gateway orchestration: resolve, evaluate, and conditionally forward MCP calls."""

import json
import logging
from dataclasses import dataclass
from time import perf_counter
from typing import Any
from uuid import uuid4

from mcp_types import CallToolResult, TextContent, Tool

from app.approvals.models import ApprovalRequest
from app.approvals.service import (
    ApprovalAlreadyConsumedError,
    ApprovalArgumentMismatchError,
    ApprovalDeniedError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ApprovalService,
    ApprovalTimedOutError,
)
from app.auth.identity import AgentIdentity
from app.auth.permissions import PermissionEvaluator
from app.audit.service import AuditService
from app.gateway.downstream import (
    DownstreamMCPClient,
    DownstreamTimeoutError,
    DownstreamUnavailableError,
)
from app.gateway.errors import GatewayError, GatewayErrorCode
from app.gateway.metadata import ToolMetadataRegistry
from app.gateway.router import (
    GatewayToolRoute,
    InvalidGatewayToolName,
    build_gateway_tool_name,
    parse_gateway_tool_name,
)
from app.gateway.servers import DownstreamServerRegistry
from app.policy.models import PolicyAction
from app.security.evaluator import SecurityEvaluator
from app.security.models import ToolRequestContext
from app.sessions.service import SessionOwnershipMismatchError, SessionSecurityService


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
        audit_service: AuditService | None = None,
        session_service: SessionSecurityService | None = None,
        approval_service: ApprovalService | None = None,
    ) -> None:
        self._servers = servers
        self._metadata = metadata
        self._permissions = permissions
        self._security_evaluator = security_evaluator
        self._downstream_client = downstream_client
        self._audit_service = audit_service
        self._session_service = session_service
        self._approval_service = approval_service

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

    @property
    def audit_service(self) -> AuditService | None:
        return self._audit_service

    @property
    def session_service(self) -> SessionSecurityService | None:
        return self._session_service

    @property
    def approval_service(self) -> ApprovalService | None:
        return self._approval_service

    def record_approval_event(self, event_type: str, approval: ApprovalRequest, actor_id: str) -> None:
        self._record_approval_event(event_type, approval, actor_id)

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
        session_context = None
        if self._session_service is not None:
            try:
                session_context = self._session_service.get_or_create(session_id, agent.agent_id)
            except SessionOwnershipMismatchError:
                return self._error(
                    GatewayErrorCode.SESSION_OWNERSHIP_MISMATCH,
                    "Session belongs to a different agent.",
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
            sensitive_data_involved=(
                metadata.data_classification in {"confidential", "secret", "restricted"}
                or bool(session_context and session_context.sensitive_data_accessed)
            ),
            session_sensitive_data_accessed=bool(session_context and session_context.sensitive_data_accessed),
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

        if self._session_service is not None:
            try:
                self._session_service.record_evaluation(
                    session_id,
                    agent.agent_id,
                    gateway_tool_name,
                    evaluation.risk.score,
                    metadata.external_destination,
                )
            except SessionOwnershipMismatchError:
                return self._error(
                    GatewayErrorCode.SESSION_OWNERSHIP_MISMATCH,
                    "Session belongs to a different agent.",
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
            approval = None
            if evaluation.final_decision is PolicyAction.REQUIRE_APPROVAL and self._approval_service is not None:
                approval = self._approval_service.create(
                    request_id=request_id,
                    session_id=session_id,
                    agent_id=agent.agent_id,
                    gateway_tool_name=gateway_tool_name,
                    downstream_server=route.server_id,
                    downstream_tool_name=route.downstream_tool_name,
                    arguments=arguments,
                    risk_score=evaluation.risk.score,
                    risk_level=evaluation.risk.level.value,
                    risk_factors=[factor.model_dump() for factor in evaluation.risk.factors],
                    matched_policy=evaluation.policy.matched_policy if evaluation.policy else None,
                    workflow_id=evaluation.policy.approval_workflow if evaluation.policy else "default-high-risk-workflow",
                    reason=evaluation.reason,
                )
            self._record_audit(
                "TOOL_DECISION",
                context=context,
                gateway_tool_name=gateway_tool_name,
                route=route,
                evaluation=evaluation,
                approval=approval,
                execution_status="PENDING_APPROVAL" if approval else "BLOCKED",
                error_code=code.value,
                error_message=evaluation.reason,
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
                approval_id=approval.approval_id if approval else None,
            )

        self._record_audit(
            "TOOL_DECISION",
            context=context,
            gateway_tool_name=gateway_tool_name,
            route=route,
            evaluation=evaluation,
            execution_status="PENDING_EXECUTION",
        )
        started_at = perf_counter()
        try:
            downstream_result = await self._downstream_client.call_tool(
                route.server_id, route.downstream_tool_name, arguments
            )
        except DownstreamTimeoutError:
            self._record_audit(
                "TOOL_EXECUTION",
                context=context,
                gateway_tool_name=gateway_tool_name,
                route=route,
                evaluation=evaluation,
                execution_status="TIMEOUT",
                downstream_status="TIMEOUT",
                error_code=GatewayErrorCode.DOWNSTREAM_TIMEOUT.value,
                error_message="The downstream MCP server timed out.",
            )
            return self._error(
                GatewayErrorCode.DOWNSTREAM_TIMEOUT,
                "The downstream MCP server timed out.",
                request_id,
                gateway_tool_name,
            )
        except DownstreamUnavailableError:
            self._record_audit(
                "TOOL_EXECUTION",
                context=context,
                gateway_tool_name=gateway_tool_name,
                route=route,
                evaluation=evaluation,
                execution_status="DOWNSTREAM_FAILED",
                downstream_status="UNAVAILABLE",
                error_code=GatewayErrorCode.DOWNSTREAM_UNAVAILABLE.value,
                error_message="The downstream MCP server is unavailable.",
            )
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
        latency_ms = int((perf_counter() - started_at) * 1000)
        self._record_audit(
            "TOOL_EXECUTION",
            context=context,
            gateway_tool_name=gateway_tool_name,
            route=route,
            evaluation=evaluation,
            execution_status="EXECUTED",
            downstream_status="SUCCESS",
            latency_ms=latency_ms,
        )
        if (
            self._session_service is not None
            and metadata.output_classification.lower() in {"confidential", "restricted", "secret"}
        ):
            self._session_service.mark_sensitive_access(
                session_id,
                agent.agent_id,
                metadata.sensitive_categories,
            )
            logger.info(
                "SESSION_SENSITIVE_ACCESS session_id=%s agent=%s tool=%s classification=%s",
                session_id,
                agent.agent_id,
                route.downstream_tool_name,
                metadata.output_classification.upper(),
            )
        return GatewayCallResult(result=downstream_result)

    async def execute_approved_action(
        self,
        agent: AgentIdentity,
        approval_id: str,
        arguments: dict[str, Any] | None = None,
    ) -> GatewayCallResult:
        """Execute one claimed approval without reopening general policy authorization."""

        if self._approval_service is None:
            return self._error(
                GatewayErrorCode.APPROVAL_NOT_FOUND,
                "Approval service is unavailable.",
                str(uuid4()),
                "approval-execution",
            )
        try:
            claim = self._approval_service.claim_execution(approval_id, agent.agent_id, arguments)
        except ApprovalNotFoundError:
            return self._approval_error(GatewayErrorCode.APPROVAL_NOT_FOUND, approval_id, agent)
        except ApprovalExpiredError:
            return self._approval_error(GatewayErrorCode.APPROVAL_EXPIRED, approval_id, agent)
        except ApprovalTimedOutError:
            return self._approval_error(GatewayErrorCode.APPROVAL_TIMED_OUT, approval_id, agent)
        except ApprovalArgumentMismatchError:
            return self._approval_error(GatewayErrorCode.APPROVAL_ARGUMENT_MISMATCH, approval_id, agent)
        except ApprovalAlreadyConsumedError:
            return self._approval_error(GatewayErrorCode.APPROVAL_ALREADY_CONSUMED, approval_id, agent)
        except ApprovalDeniedError:
            return self._approval_error(GatewayErrorCode.APPROVAL_DENIED, approval_id, agent)

        approval = claim.approval
        route = GatewayToolRoute(approval.downstream_server, approval.downstream_tool_name)
        try:
            downstream_result = await self._downstream_client.call_tool(
                route.server_id, route.downstream_tool_name, claim.original_arguments
            )
        except (DownstreamTimeoutError, DownstreamUnavailableError):
            self._approval_service.complete_execution(approval_id, success=False, actor_id=agent.agent_id)
            return self._error(
                GatewayErrorCode.DOWNSTREAM_UNAVAILABLE,
                "The downstream MCP server is unavailable.",
                approval.request_id,
                approval.gateway_tool_name,
                approval_id=approval_id,
            )

        self._approval_service.complete_execution(approval_id, success=True, actor_id=agent.agent_id)
        logger.info("APPROVAL_EXECUTED approval_id=%s", approval_id)
        return GatewayCallResult(result=downstream_result)

    def _approval_error(
        self, code: GatewayErrorCode, approval_id: str, agent: AgentIdentity
    ) -> GatewayCallResult:
        return self._error(code, "Approval cannot be executed.", str(uuid4()), "approval-execution", approval_id=approval_id)

    def _record_audit(
        self,
        event_type: str,
        *,
        context: ToolRequestContext,
        gateway_tool_name: str,
        route: GatewayToolRoute,
        evaluation: Any,
        approval: ApprovalRequest | None = None,
        execution_status: str,
        downstream_status: str | None = None,
        latency_ms: int | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        if self._audit_service is None:
            return
        self._audit_service.record(
            event_type,
            arguments=context.arguments,
            request_id=context.request_id,
            session_id=context.session_id,
            agent_id=context.agent.agent_id,
            agent_role=context.agent.role,
            environment=context.agent.environment,
            gateway_tool_name=gateway_tool_name,
            downstream_server=route.server_id,
            downstream_tool_name=route.downstream_tool_name,
            permission_allowed=evaluation.permission.allowed,
            permission_reason=evaluation.permission.reason,
            risk_score=evaluation.risk.score,
            risk_level=evaluation.risk.level.value,
            risk_factors=[factor.model_dump() for factor in evaluation.risk.factors],
            matched_policy=evaluation.policy.matched_policy if evaluation.policy else None,
            policy_action=evaluation.policy.decision.value if evaluation.policy else None,
            decision_reason=evaluation.reason,
            final_decision=evaluation.final_decision.value,
            approval_id=approval.approval_id if approval else None,
            approval_status=approval.status.value if approval else None,
            execution_status=execution_status,
            downstream_status=downstream_status,
            latency_ms=latency_ms,
            error_code=error_code,
            error_message=error_message,
        )

    def _record_approval_event(
        self, event_type: str, approval: ApprovalRequest, actor_id: str
    ) -> None:
        if self._audit_service is None:
            return
        self._audit_service.record(
            event_type,
            request_id=approval.request_id,
            session_id=approval.session_id,
            agent_id=approval.agent_id,
            gateway_tool_name=approval.gateway_tool_name,
            downstream_server=approval.downstream_server,
            downstream_tool_name=approval.downstream_tool_name,
            approval_id=approval.approval_id,
            approval_status=approval.status.value,
            execution_status=approval.execution_status,
            decision_reason=approval.reason,
            error_message=f"actor={actor_id}",
        )

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
