"""Typed request context shared by all security evaluators."""

from typing import Any

from pydantic import BaseModel, Field

from app.auth.identity import AgentIdentity


class ToolRequestContext(BaseModel):
    request_id: str
    session_id: str
    agent: AgentIdentity
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    destination_type: str | None = None
    data_classification: str | None = None
    is_write_operation: bool = False
    is_external_destination: bool = False
    sensitive_data_involved: bool = False

