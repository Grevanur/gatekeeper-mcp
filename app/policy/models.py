"""Validated policy definitions and decision responses."""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from app.risk.models import RiskLevel


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class PolicyMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str | None = None
    agent_id: str | None = None
    role: str | None = None
    environment: str | None = None
    risk_level: RiskLevel | None = None
    minimum_risk_level: RiskLevel | None = None
    is_external_destination: bool | None = None
    sensitive_data_involved: bool | None = None
    is_write_operation: bool | None = None
    session_sensitive_data_accessed: bool | None = None


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    priority: int
    match: PolicyMatch = Field(default_factory=PolicyMatch)
    action: PolicyAction
    reason: str


class PoliciesConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policies: list[PolicyRule] = Field(min_length=1)


class PolicyDecision(BaseModel):
    decision: PolicyAction
    matched_policy: str | None
    reason: str
