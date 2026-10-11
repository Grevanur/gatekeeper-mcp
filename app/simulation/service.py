"""Pure simulation service: it deliberately has no downstream-client dependency."""

from uuid import uuid4

from app.auth.identity import AgentIdentity, AgentsConfiguration
from app.security.evaluator import SecurityEvaluator
from app.security.models import ToolRequestContext
from app.simulation.models import (
    PolicyRegressionConfiguration,
    PolicyRegressionResult,
    SimulationComparison,
    SimulationComparisonRequest,
    SimulationRequest,
    SimulationResult,
)
from app.workflows.registry import WorkflowContextResolver


class SimulationService:
    def __init__(
        self,
        evaluator: SecurityEvaluator,
        agents: AgentsConfiguration,
        contexts: WorkflowContextResolver,
    ) -> None:
        self._evaluator = evaluator
        self._agents = agents
        self._contexts = contexts

    def evaluate(self, request: SimulationRequest) -> SimulationResult:
        return self._evaluate(request, self._evaluator)

    def _evaluate(self, request: SimulationRequest, evaluator: SecurityEvaluator) -> SimulationResult:
        configured = self._agents.agents.get(request.agent_id)
        if configured is None:
            raise ValueError(f"Unknown agent: {request.agent_id}")
        agent = AgentIdentity.model_validate(configured)
        workflow_context = self._contexts.resolve(
            gateway_environment=agent.environment,
            declared=request.workflow_context,
        )
        evaluation = evaluator.evaluate(
            ToolRequestContext(
                request_id=f"sim_{uuid4().hex}",
                session_id="simulation",
                agent=agent,
                tool_name=request.tool_name,
                arguments=request.arguments,
                is_write_operation=request.is_write_operation,
                is_external_destination=request.is_external_destination,
                sensitive_data_involved=request.sensitive_data_involved,
                workflow_context=workflow_context,
            )
        )
        policy = evaluation.policy
        return SimulationResult(
            decision=evaluation.final_decision,
            reason=evaluation.reason,
            risk=evaluation.risk,
            policy_id=policy.policy_id if policy else None,
            policy_version=policy.policy_version if policy else None,
            approval_workflow=policy.approval_workflow if policy else None,
            workflow_context=workflow_context,
        )

    def compare(self, request: SimulationComparisonRequest) -> SimulationComparison:
        baseline = self.evaluate(request.baseline)
        candidate_evaluator = (
            self._evaluator.with_policy_configuration(request.candidate_policies)
            if request.candidate_policies is not None
            else self._evaluator
        )
        candidate = self._evaluate(request.candidate, candidate_evaluator)
        tracked = (
            "environment",
            "workflow_id",
            "business_criticality",
            "customer_impact",
            "estimated_records_affected",
            "after_hours",
            "emergency",
            "tags",
        )
        changed_context = [
            field for field in tracked
            if getattr(baseline.workflow_context, field) != getattr(candidate.workflow_context, field)
        ]
        before = {factor.name for factor in baseline.risk.factors}
        after = {factor.name for factor in candidate.risk.factors}
        changed_factors = sorted(before.symmetric_difference(after))
        changed = baseline.decision != candidate.decision
        explanation = (
            f"Decision changed from {baseline.decision.value} to {candidate.decision.value}."
            if changed
            else "Decision did not change; the displayed context and risk-factor differences explain the comparison."
        )
        return SimulationComparison(
            baseline=baseline,
            candidate=candidate,
            changed_context_fields=changed_context,
            changed_risk_factors=changed_factors,
            decision_changed=changed,
            explanation=explanation,
        )

    def run_regressions(self, configuration: PolicyRegressionConfiguration) -> list[PolicyRegressionResult]:
        results: list[PolicyRegressionResult] = []
        for scenario in configuration.scenarios:
            actual = self.evaluate(scenario.request).decision
            results.append(
                PolicyRegressionResult(
                    scenario_id=scenario.id,
                    expected=scenario.expected_decision,
                    actual=actual,
                    passed=actual is scenario.expected_decision,
                )
            )
        return results
