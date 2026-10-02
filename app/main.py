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
    app.state.security_evaluator = security_evaluator
    app.state.identity_authenticator = security_evaluator.identity_authenticator
    initialize_database()
    yield


settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)


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
