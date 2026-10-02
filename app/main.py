"""FastAPI entry point for the MCP Zero-Trust Gateway."""

from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.config import get_settings
from app.database.db import SessionLocal, initialize_database
from app.auth.identity import AgentIdentity, get_current_agent
from app.auth.identity import load_agents_configuration
from app.auth.permissions import PermissionEvaluator
from app.gateway.downstream import MCPDownstreamClient
from app.gateway.mcp_server import GatewayMCPMount, create_gateway_mcp_server
from app.gateway.metadata import ToolMetadataRegistry
from app.gateway.servers import DownstreamServerRegistry
from app.gateway.service import MCPGatewayService
from app.security.evaluator import SecurityEvaluation, SecurityEvaluator
from app.security.models import ToolRequestContext


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
    )
    app.state.security_evaluator = security_evaluator
    app.state.identity_authenticator = security_evaluator.identity_authenticator
    app.state.gateway_service = gateway_service
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
