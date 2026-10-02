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


class RiskConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_risk: dict[str, RiskValue]
    risk_modifiers: RiskModifiers

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
