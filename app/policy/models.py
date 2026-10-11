"""Validated policy definitions and decision responses."""

from datetime import date, timedelta
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.risk.models import RiskLevel


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class PolicyStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    DISABLED = "DISABLED"


class PolicyReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    last_reviewed_at: date
    review_interval_days: int = Field(gt=0)

    @property
    def next_review_due_at(self) -> date:
        return self.last_reviewed_at + timedelta(days=self.review_interval_days)


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
    workflow_id: str | None = None
    business_criticality: str | None = None
    customer_impact: bool | None = None
    minimum_records_affected: int | None = Field(default=None, ge=0)
    after_hours: bool | None = None
    emergency: bool | None = None
    required_tags: list[str] = Field(default_factory=list)


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    version: int = Field(gt=0)
    owner: str = Field(min_length=1)
    status: PolicyStatus = PolicyStatus.ACTIVE
    review: PolicyReview
    change_reason: str = Field(min_length=1)
    priority: int
    match: PolicyMatch = Field(default_factory=PolicyMatch)
    action: PolicyAction
    approval_workflow: str | None = None
    reason: str

    @model_validator(mode="after")
    def validate_approval_workflow(self) -> "PolicyRule":
        if self.action is PolicyAction.REQUIRE_APPROVAL and not self.approval_workflow:
            raise ValueError("REQUIRE_APPROVAL policies require an approval_workflow.")
        if self.action is not PolicyAction.REQUIRE_APPROVAL and self.approval_workflow is not None:
            raise ValueError("approval_workflow is only valid for REQUIRE_APPROVAL policies.")
        return self


class PoliciesConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policies: list[PolicyRule] = Field(min_length=1)

    @model_validator(mode="after")
    def require_unique_ids(self) -> "PoliciesConfiguration":
        ids = [policy.id for policy in self.policies]
        if len(ids) != len(set(ids)):
            raise ValueError("Policy IDs must be unique.")
        return self


class PolicyDecision(BaseModel):
    decision: PolicyAction
    matched_policy: str | None
    reason: str
    approval_workflow: str | None = None
    policy_id: str | None = None
    policy_version: int | None = None
    matched_policies: list[str] = Field(default_factory=list)
    error_code: str | None = None
