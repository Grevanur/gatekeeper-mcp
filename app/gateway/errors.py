"""Stable, client-safe errors emitted by the MCP gateway."""

from enum import Enum

from pydantic import BaseModel


class GatewayErrorCode(str, Enum):
    INVALID_AGENT = "INVALID_AGENT"
    INVALID_TOOL_NAME = "INVALID_TOOL_NAME"
    UNKNOWN_SERVER = "UNKNOWN_SERVER"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    POLICY_DENIED = "POLICY_DENIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    DOWNSTREAM_UNAVAILABLE = "DOWNSTREAM_UNAVAILABLE"
    DOWNSTREAM_TIMEOUT = "DOWNSTREAM_TIMEOUT"
    SECURITY_EVALUATION_FAILED = "SECURITY_EVALUATION_FAILED"


class GatewayError(BaseModel):
    code: GatewayErrorCode
    message: str
    request_id: str
    tool_name: str
    decision: str | None = None
    matched_policy: str | None = None
    risk_score: int | None = None
    risk_level: str | None = None

