"""Typed, provenance-aware workflow context."""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ContextSource(str, Enum):
    GATEWAY_DERIVED = "gateway_derived"
    WORKFLOW_REGISTRY = "workflow_registry"
    CALLER_DECLARED = "caller_declared"


class BusinessCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WorkflowDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    business_criticality: BusinessCriticality = BusinessCriticality.LOW
    customer_impact: bool = False
    tags: list[str] = Field(default_factory=list)
    time_zone: str = "UTC"
    workday_start_hour: int = Field(default=9, ge=0, le=23)
    workday_end_hour: int = Field(default=17, ge=1, le=24)


class WorkflowRegistryConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflows: list[WorkflowDefinition] = Field(min_length=1)


class WorkflowContextInput(BaseModel):
    """Caller-declared hints. They are merged conservatively with trusted data."""

    model_config = ConfigDict(extra="forbid")

    workflow_id: str | None = None
    environment: str | None = None
    business_criticality: BusinessCriticality | None = None
    customer_impact: bool | None = None
    estimated_records_affected: int | None = Field(default=None, ge=0)
    after_hours: bool | None = None
    emergency: bool | None = None
    tags: list[str] = Field(default_factory=list)


class ResolvedWorkflowContext(BaseModel):
    """Normalized context plus non-sensitive provenance and conflict labels."""

    workflow_id: str | None = None
    environment: str
    business_criticality: BusinessCriticality = BusinessCriticality.LOW
    customer_impact: bool = False
    estimated_records_affected: int = 0
    after_hours: bool = False
    emergency: bool = False
    tags: list[str] = Field(default_factory=list)
    sources: dict[str, ContextSource] = Field(default_factory=dict)
    conflicts: list[str] = Field(default_factory=list)
