"""Pydantic models for risk configuration and explanations."""

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator


RiskValue = Annotated[int, Field(ge=0, le=100)]


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskModifiers(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_destination: RiskValue
    sensitive_data: RiskValue
    production_environment: RiskValue
    write_operation: RiskValue
    unknown_tool: RiskValue
    recent_sensitive_access: RiskValue
    sensitive_to_external_transition: RiskValue
    high_business_criticality: RiskValue = 0
    critical_business_criticality: RiskValue = 0
    customer_impact: RiskValue = 0
    bulk_blast_radius: RiskValue = 0
    large_blast_radius: RiskValue = 0
    after_hours: RiskValue = 0
    emergency_change: RiskValue = 0


class RiskConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_risk: dict[str, RiskValue]
    risk_modifiers: RiskModifiers
    bulk_records_threshold: int = Field(default=1_000, ge=1)
    large_records_threshold: int = Field(default=10_000, ge=1)

    @field_validator("tool_risk")
    @classmethod
    def require_unknown_tool_default(cls, values: dict[str, RiskValue]) -> dict[str, RiskValue]:
        if "default_unknown_tool" not in values:
            raise ValueError("tool_risk must define default_unknown_tool")
        return values


class RiskFactor(BaseModel):
    name: str
    value: int


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    factors: list[RiskFactor]
