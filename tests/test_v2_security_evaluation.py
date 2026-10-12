from app.auth.identity import AgentIdentity, load_agents_configuration
from app.approvals.binding import ApprovalBinding
from app.approvals.identity import ApproverIdentity
from app.approvals.service import ApprovalService
from app.approvals.workflows import ApprovalWorkflowRegistry
from app.audit.service import AuditService
from app.database.models import Base
from app.policy.lifecycle import PolicyLifecycleService
from app.policy.models import PoliciesConfiguration
from app.security.evaluator import SecurityEvaluator
from app.security.models import ToolRequestContext
from app.simulation.models import SimulationRequest
from app.simulation.service import SimulationService
from app.workflows.registry import WorkflowContextResolver
from evaluation.runner import run_security_scenarios
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def test_security_scenario_harness_enforces_zero_unauthorized_execution() -> None:
    result = run_security_scenarios()
    metrics = result.metrics()

    assert all(scenario.passed for scenario in result.scenarios)
    assert metrics["unauthorized_execution_successes"] == 0
    assert metrics["approval_bypass_successes"] == 0
    assert metrics["simulation_downstream_executions"] == 0
    assert metrics["policy_conflicts_failed_closed"] == 1
    exhausted = next(item for item in result.scenarios if item.scenario_id == "approval-chain-exhausted")
    assert {"APPROVAL_CREATED", "APPROVAL_ESCALATED", "APPROVAL_TIMED_OUT", "APPROVAL_FINAL_DENY"} <= set(exhausted.detail.split(","))


def test_simulation_matches_real_security_evaluation_without_execution() -> None:
    agents = load_agents_configuration("config/agents.yaml")
    evaluator = SecurityEvaluator.from_config_directory("config")
    resolver = WorkflowContextResolver.from_config_file("config/workflows.yaml")
    simulation = SimulationService(evaluator, agents, resolver)
    simulated = simulation.evaluate(SimulationRequest(tool_name="tickets.search"))
    agent = AgentIdentity(agent_id="admin-agent", owner="demo-user", role="admin", environment="development")
    real = evaluator.evaluate(ToolRequestContext(
        request_id="real", session_id="real", agent=agent, tool_name="tickets.search",
        workflow_context=resolver.resolve(gateway_environment=agent.environment),
    ))

    assert simulated.decision is real.final_decision
    assert simulated.downstream_executed is False


def test_pending_approval_remains_bound_to_the_policy_version_that_created_it() -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    audit = AuditService(factory)
    policy_v2 = PoliciesConfiguration.model_validate({"policies": [{
        "id": "evaluation-policy", "name": "Evaluation policy", "description": "Version test",
        "version": 2, "owner": "security", "status": "ACTIVE",
        "review": {"last_reviewed_at": "2026-01-01", "review_interval_days": 90},
        "change_reason": "Candidate activated after request creation.", "priority": 1,
        "match": {}, "action": "REQUIRE_APPROVAL", "approval_workflow": "default-high-risk-workflow", "reason": "Review required.",
    }]})
    binding = ApprovalBinding.create(
        agent_id="admin-agent", session_id="version", gateway_tool_name="messaging.external.send",
        downstream_server="messaging", downstream_tool_name="external.send", arguments={"destination": "security@company.com"},
        destination="security@company.com", destination_type="email", environment="development",
        security_context={"risk_level": "HIGH"}, policy_id="evaluation-policy", policy_version=1,
    )
    approvals = ApprovalService(factory, ApprovalWorkflowRegistry.from_config_file("config/approval_workflows.yaml"), audit)
    request = approvals.create(
        request_id="version", session_id="version", agent_id="admin-agent", gateway_tool_name="messaging.external.send",
        downstream_server="messaging", downstream_tool_name="external.send", arguments={"destination": "security@company.com"},
        risk_score=80, risk_level="HIGH", risk_factors=[], matched_policy="evaluation-policy", workflow_id="default-high-risk-workflow",
        reason="Review required.", binding=binding, policy_id="evaluation-policy", policy_version=1,
    )
    PolicyLifecycleService(factory, policy_v2, audit).synchronize()
    approvals.approve(request.approval_id, ApproverIdentity(subject_id="security-admin-1", display_name="Admin", role="security_admin"))
    claim = approvals.claim_execution(request.approval_id, "admin-agent", binding=binding)

    assert claim.approval.policy_version == 1
    assert claim.approval.binding is not None
    assert claim.approval.binding.policy_version == 1
