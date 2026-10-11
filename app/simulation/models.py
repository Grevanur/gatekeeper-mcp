"""API-safe models for non-executing security simulations."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.policy.models import PolicyAction
from app.policy.models import PoliciesConfiguration
from app.risk.models import RiskAssessment
from app.workflows.models import ResolvedWorkflowContext, WorkflowContextInput


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = "admin-agent"
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    is_write_operation: bool = False
    is_external_destination: bool = False
    sensitive_data_involved: bool = False
    workflow_context: WorkflowContextInput = Field(default_factory=WorkflowContextInput)


class SimulationResult(BaseModel):
    simulated: bool = True
    downstream_executed: bool = False
    decision: PolicyAction
    reason: str
    risk: RiskAssessment
    policy_id: str | None = None
    policy_version: int | None = None
    approval_workflow: str | None = None
    workflow_context: ResolvedWorkflowContext


class SimulationComparisonRequest(BaseModel):
    baseline: SimulationRequest
    candidate: SimulationRequest
    candidate_policies: PoliciesConfiguration | None = None


class SimulationComparison(BaseModel):
    baseline: SimulationResult
    candidate: SimulationResult
    changed_context_fields: list[str]
    changed_risk_factors: list[str]
    decision_changed: bool
    explanation: str


class PolicyRegressionScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    request: SimulationRequest
    expected_decision: PolicyAction


class PolicyRegressionConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenarios: list[PolicyRegressionScenario] = Field(min_length=1)


class PolicyRegressionResult(BaseModel):
    scenario_id: str
    expected: PolicyAction
    actual: PolicyAction
    passed: bool
