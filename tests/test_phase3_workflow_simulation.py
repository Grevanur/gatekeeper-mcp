from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.auth.identity import AgentIdentity, load_agents_configuration
from app.configuration import load_yaml_mapping
from app.policy.engine import PolicyEngine
from app.policy.loader import load_policies_configuration
from app.policy.models import PolicyAction
from app.policy.models import PoliciesConfiguration
from app.risk.engine import RiskEngine
from app.security.evaluator import SecurityEvaluator
from app.security.models import ToolRequestContext
from app.simulation.models import (
    PolicyRegressionConfiguration,
    SimulationComparisonRequest,
    SimulationRequest,
)
from app.simulation.service import SimulationService
from app.workflows.models import WorkflowContextInput
from app.workflows.registry import UnknownWorkflowError, WorkflowContextResolver
from app.main import app


def _resolver() -> WorkflowContextResolver:
    return WorkflowContextResolver.from_config_file("config/workflows.yaml")


def _simulation() -> SimulationService:
    return SimulationService(
        SecurityEvaluator.from_config_directory("config"),
        load_agents_configuration("config/agents.yaml"),
        _resolver(),
    )


def test_trusted_environment_and_registry_context_override_downgrades() -> None:
    context = _resolver().resolve(
        gateway_environment="production",
        declared=WorkflowContextInput(
            workflow_id="critical-production-change",
            environment="development",
            business_criticality="low",
            customer_impact=False,
        ),
        now=datetime(2026, 10, 12, 15, tzinfo=timezone.utc),
    )

    assert context.environment == "production"
    assert context.business_criticality.value == "critical"
    assert context.customer_impact is True
    assert {"environment", "business_criticality", "customer_impact"} <= set(context.conflicts)
    assert context.sources["environment"].value == "gateway_derived"


def test_after_hours_is_derived_from_registered_timezone_and_cannot_be_downgraded() -> None:
    context = _resolver().resolve(
        gateway_environment="production",
        declared=WorkflowContextInput(workflow_id="customer-data-maintenance", after_hours=False),
        now=datetime(2026, 10, 11, 16, tzinfo=timezone.utc),  # Sunday in New York
    )
    assert context.after_hours is True


def test_unknown_workflow_fails_closed() -> None:
    with pytest.raises(UnknownWorkflowError):
        _resolver().resolve(
            gateway_environment="production",
            declared=WorkflowContextInput(workflow_id="not-registered"),
        )


def test_workflow_context_changes_risk_and_policy_for_same_tool() -> None:
    simulation = _simulation()
    development = simulation.evaluate(
        SimulationRequest(
            tool_name="database.update",
            is_write_operation=True,
            workflow_context=WorkflowContextInput(workflow_id="routine-maintenance"),
        )
    )
    production = simulation.evaluate(
        SimulationRequest(
            agent_id="production-admin",
            tool_name="database.update",
            is_write_operation=True,
            workflow_context=WorkflowContextInput(
                workflow_id="customer-data-maintenance", estimated_records_affected=5000
            ),
        )
    )
    critical = simulation.evaluate(
        SimulationRequest(
            agent_id="production-admin",
            tool_name="database.update",
            is_write_operation=True,
            workflow_context=WorkflowContextInput(
                workflow_id="critical-production-change", after_hours=True, estimated_records_affected=100000
            ),
        )
    )

    assert [development.decision, production.decision, critical.decision] == [
        PolicyAction.ALLOW,
        PolicyAction.REQUIRE_APPROVAL,
        PolicyAction.DENY,
    ]
    assert development.risk.score < production.risk.score <= critical.risk.score
    assert all(result.downstream_executed is False for result in (development, production, critical))


def test_workflow_policy_matcher_is_deterministic() -> None:
    agent = AgentIdentity(agent_id="production-admin", owner="demo-user", role="admin", environment="production")
    workflow = _resolver().resolve(
        gateway_environment="production",
        declared=WorkflowContextInput(workflow_id="customer-data-maintenance", estimated_records_affected=1000),
        now=datetime(2026, 10, 12, 15, tzinfo=timezone.utc),
    )
    context = ToolRequestContext(
        request_id="phase3", session_id="phase3", agent=agent, tool_name="database.update",
        is_write_operation=True, workflow_context=workflow,
    )
    risk = RiskEngine.from_config_file("config/risk.yaml").assess(context)
    decision = PolicyEngine(load_policies_configuration("config/policies.yaml")).evaluate(context, risk)
    assert decision.policy_id == "bulk-production-update-approval"
    assert decision.decision is PolicyAction.REQUIRE_APPROVAL


def test_comparison_reports_safe_context_and_decision_differences() -> None:
    comparison = _simulation().compare(
        SimulationComparisonRequest(
            baseline=SimulationRequest(
                tool_name="database.update", is_write_operation=True,
                workflow_context=WorkflowContextInput(workflow_id="routine-maintenance"),
            ),
            candidate=SimulationRequest(
                agent_id="production-admin", tool_name="database.update", is_write_operation=True,
                workflow_context=WorkflowContextInput(
                    workflow_id="customer-data-maintenance", estimated_records_affected=5000
                ),
            ),
        )
    )
    assert comparison.decision_changed is True
    assert "environment" in comparison.changed_context_fields
    assert "bulk_blast_radius" in comparison.changed_risk_factors
    assert "ALLOW to REQUIRE_APPROVAL" in comparison.explanation


def test_candidate_policy_configuration_is_isolated_and_changes_only_candidate_result() -> None:
    candidate = load_yaml_mapping(__import__("pathlib").Path("config/policies.yaml"))
    rule = next(item for item in candidate["policies"] if item["id"] == "routine-development-update-allow")
    rule.update({
        "version": 2,
        "action": "REQUIRE_APPROVAL",
        "approval_workflow": "default-high-risk-workflow",
        "change_reason": "Candidate review control.",
    })
    request = SimulationRequest(
        tool_name="database.update", is_write_operation=True,
        workflow_context=WorkflowContextInput(workflow_id="routine-maintenance"),
    )
    comparison = _simulation().compare(SimulationComparisonRequest(
        baseline=request, candidate=request, candidate_policies=PoliciesConfiguration.model_validate(candidate)
    ))
    assert comparison.baseline.decision is PolicyAction.ALLOW
    assert comparison.candidate.decision is PolicyAction.REQUIRE_APPROVAL
    assert comparison.candidate.downstream_executed is False


def test_declared_regressions_pass_and_detect_an_unexpected_decision() -> None:
    service = _simulation()
    configuration = PolicyRegressionConfiguration.model_validate(
        load_yaml_mapping(__import__("pathlib").Path("config/policy_scenarios.yaml"))
    )
    assert all(result.passed for result in service.run_regressions(configuration))
    bad = configuration.model_copy(deep=True)
    bad.scenarios[1].expected_decision = PolicyAction.ALLOW
    result = service.run_regressions(bad)[1]
    assert result.passed is False


def test_simulation_api_is_admin_only_and_never_executes_downstream() -> None:
    payload = {
        "tool_name": "database.update",
        "is_write_operation": True,
        "workflow_context": {"workflow_id": "routine-maintenance"},
    }
    with TestClient(app) as client:
        denied = client.post("/simulate/evaluate", json=payload, headers={"Authorization": "Bearer dev-support-token"})
        response = client.post("/simulate/evaluate", json=payload, headers={"Authorization": "Bearer dev-admin-token"})
    assert denied.status_code == 403
    assert response.status_code == 200
    assert response.json()["downstream_executed"] is False
