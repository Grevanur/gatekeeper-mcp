"""FastAPI entry point for the MCP Zero-Trust Gateway."""

from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.config import get_settings
from app.database.db import SessionLocal, initialize_database
from app.approvals.models import ApprovalRequest
from app.approvals.service import ApprovalNotFoundError, ApprovalService
from app.auth.identity import AgentIdentity, get_current_agent
from app.auth.identity import load_agents_configuration
from app.auth.permissions import PermissionEvaluator
from app.audit.models import AuditEvent
from app.audit.service import AuditService
from app.gateway.downstream import MCPDownstreamClient
from app.gateway.mcp_server import GatewayMCPMount, create_gateway_mcp_server
from app.gateway.metadata import ToolMetadataRegistry
from app.gateway.servers import DownstreamServerRegistry
from app.gateway.service import MCPGatewayService
from app.gateway.errors import GatewayError, GatewayErrorCode
from app.security.evaluator import SecurityEvaluation, SecurityEvaluator
from app.security.models import ToolRequestContext
from app.sessions.models import SessionSecurityContext
from app.sessions.service import (
    SessionNotFoundError,
    SessionOwnershipMismatchError,
    SessionSecurityService,
)


class HealthResponse(BaseModel):
    status: str
    service: str
    environment: str
    database: str


class SecurityEvaluationRequest(BaseModel):
    """Development-only input for exercising the security core."""

    session_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    destination_type: str | None = None
    data_classification: str | None = None
    is_write_operation: bool = False
    is_external_destination: bool = False
    sensitive_data_involved: bool = False


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialize persistence before accepting gateway traffic."""

    security_evaluator = SecurityEvaluator.from_config_directory(settings.config_directory)
    agents = load_agents_configuration(settings.config_directory / "agents.yaml")
    servers = DownstreamServerRegistry.from_config_file(settings.config_directory / "mcp_servers.yaml")
    gateway_service = MCPGatewayService(
        servers=servers,
        metadata=ToolMetadataRegistry.from_config_file(settings.config_directory / "tool_metadata.yaml"),
        permissions=PermissionEvaluator(agents),
        security_evaluator=security_evaluator,
        downstream_client=MCPDownstreamClient(servers, settings.downstream_timeout_seconds),
        audit_service=AuditService(SessionLocal),
        session_service=SessionSecurityService(SessionLocal),
        approval_service=ApprovalService(SessionLocal, settings.approval_ttl_seconds),
    )
    app.state.security_evaluator = security_evaluator
    app.state.identity_authenticator = security_evaluator.identity_authenticator
    app.state.gateway_service = gateway_service
    app.state.audit_service = gateway_service.audit_service
    app.state.session_security_service = gateway_service.session_service
    app.state.approval_service = gateway_service.approval_service
    initialize_database()
    mcp_server = create_gateway_mcp_server(lambda: app.state.gateway_service)
    mcp_app = mcp_server.streamable_http_app(streamable_http_path="/")
    gateway_mcp_mount.set_app(mcp_app)
    try:
        async with mcp_app.router.lifespan_context(mcp_app):
            yield
    finally:
        gateway_mcp_mount.clear_app()


settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
gateway_mcp_mount = GatewayMCPMount()
app.mount("/mcp", gateway_mcp_mount)


@app.get("/health", response_model=HealthResponse, tags=["operations"])
def health_check() -> HealthResponse:
    """Report whether the gateway foundation and its database are reachable."""

    try:
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
    except Exception as error:  # pragma: no cover - requires a broken database at runtime
        raise HTTPException(status_code=503, detail="Database unavailable") from error

    return HealthResponse(
        status="ok",
        service=settings.app_name,
        environment=settings.environment,
        database="connected",
    )


@app.post(
    "/security/evaluate",
    response_model=SecurityEvaluation,
    tags=["development"],
    summary="Development-only deterministic security evaluation",
)
def evaluate_security(
    payload: SecurityEvaluationRequest,
    agent: AgentIdentity = Depends(get_current_agent),
) -> SecurityEvaluation:
    """Evaluate a typed tool request without calling an MCP server."""

    context = ToolRequestContext(
        request_id=str(uuid4()),
        session_id=payload.session_id,
        agent=agent,
        tool_name=payload.tool_name,
        arguments=payload.arguments,
        destination_type=payload.destination_type,
        data_classification=payload.data_classification,
        is_write_operation=payload.is_write_operation,
        is_external_destination=payload.is_external_destination,
        sensitive_data_involved=payload.sensitive_data_involved,
    )
    return app.state.security_evaluator.evaluate(context)


def _require_admin(agent: AgentIdentity) -> None:
    if agent.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")


def _error_response(status_code: int, code: GatewayErrorCode, message: str, tool_name: str) -> JSONResponse:
    error = GatewayError(
        code=code,
        message=message,
        request_id=str(uuid4()),
        tool_name=tool_name,
    )
    return JSONResponse(status_code=status_code, content=error.model_dump(mode="json"))


@app.get("/audit/events", response_model=list[AuditEvent], tags=["audit"])
def list_audit_events(
    agent_id: str | None = None,
    session_id: str | None = None,
    decision: str | None = None,
    risk_level: str | None = None,
    tool: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    agent: AgentIdentity = Depends(get_current_agent),
) -> list[AuditEvent]:
    _require_admin(agent)
    return app.state.audit_service.list_events(
        agent_id=agent_id,
        session_id=session_id,
        decision=decision,
        risk_level=risk_level,
        tool=tool,
        limit=limit,
        offset=offset,
    )


@app.get("/audit/events/{event_id}", response_model=AuditEvent, tags=["audit"])
def get_audit_event(event_id: str, agent: AgentIdentity = Depends(get_current_agent)) -> AuditEvent | JSONResponse:
    _require_admin(agent)
    event = app.state.audit_service.get_event(event_id)
    if event is None:
        return _error_response(404, GatewayErrorCode.AUDIT_EVENT_NOT_FOUND, "Audit event not found.", event_id)
    return event


@app.get("/approvals", response_model=list[ApprovalRequest], tags=["approvals"])
def list_approvals(agent: AgentIdentity = Depends(get_current_agent)) -> list[ApprovalRequest]:
    _require_admin(agent)
    return app.state.approval_service.list()


@app.get("/approvals/{approval_id}", response_model=ApprovalRequest, tags=["approvals"])
def get_approval(
    approval_id: str, agent: AgentIdentity = Depends(get_current_agent)
) -> ApprovalRequest | JSONResponse:
    _require_admin(agent)
    try:
        return app.state.approval_service.get(approval_id)
    except ApprovalNotFoundError:
        return _error_response(404, GatewayErrorCode.APPROVAL_NOT_FOUND, "Approval request not found.", approval_id)


@app.post("/approvals/{approval_id}/approve", response_model=ApprovalRequest, tags=["approvals"])
def approve_request(
    approval_id: str, agent: AgentIdentity = Depends(get_current_agent)
) -> ApprovalRequest | JSONResponse:
    _require_admin(agent)
    try:
        approval = app.state.approval_service.approve(approval_id, agent.agent_id)
    except ApprovalNotFoundError:
        return _error_response(404, GatewayErrorCode.APPROVAL_NOT_FOUND, "Approval request not found.", approval_id)
    except PermissionError as error:
        return _error_response(409, GatewayErrorCode.APPROVAL_DENIED, str(error), approval_id)
    app.state.gateway_service.record_approval_event("APPROVAL_APPROVED", approval, agent.agent_id)
    return approval


@app.post("/approvals/{approval_id}/deny", response_model=ApprovalRequest, tags=["approvals"])
def deny_request(
    approval_id: str, agent: AgentIdentity = Depends(get_current_agent)
) -> ApprovalRequest | JSONResponse:
    _require_admin(agent)
    try:
        approval = app.state.approval_service.deny(approval_id, agent.agent_id)
    except ApprovalNotFoundError:
        return _error_response(404, GatewayErrorCode.APPROVAL_NOT_FOUND, "Approval request not found.", approval_id)
    except PermissionError as error:
        return _error_response(409, GatewayErrorCode.APPROVAL_DENIED, str(error), approval_id)
    app.state.gateway_service.record_approval_event("APPROVAL_DENIED", approval, agent.agent_id)
    return approval


class ApprovalExecutionRequest(BaseModel):
    arguments: dict[str, Any] | None = None


@app.post("/approvals/{approval_id}/execute", tags=["approvals"])
async def execute_approval(
    approval_id: str,
    payload: ApprovalExecutionRequest | None = None,
    agent: AgentIdentity = Depends(get_current_agent),
) -> JSONResponse:
    outcome = await app.state.gateway_service.execute_approved_action(
        agent, approval_id, payload.arguments if payload is not None else None
    )
    if outcome.error is not None:
        return JSONResponse(status_code=409, content=outcome.error.model_dump(mode="json"))
    return JSONResponse(
        content={
            "approval_id": approval_id,
            "execution_status": "EXECUTED",
            "result": outcome.result.model_dump(by_alias=True, mode="json"),
        }
    )


@app.get("/sessions/{session_id}", response_model=SessionSecurityContext, tags=["sessions"])
def get_session_context(
    session_id: str, agent: AgentIdentity = Depends(get_current_agent)
) -> SessionSecurityContext | JSONResponse:
    try:
        return app.state.session_security_service.get(session_id, agent.agent_id)
    except SessionNotFoundError:
        return _error_response(404, GatewayErrorCode.SESSION_NOT_FOUND, "Session not found.", session_id)
    except SessionOwnershipMismatchError:
        return _error_response(
            403,
            GatewayErrorCode.SESSION_OWNERSHIP_MISMATCH,
            "Session belongs to a different agent.",
            session_id,
        )
