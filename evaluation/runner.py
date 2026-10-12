"""Data-oriented V2 security scenarios, reports, and a CI-friendly entry point."""

import asyncio
import json
import platform
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.approvals.binding import ApprovalBinding
from app.approvals.identity import ApproverIdentity
from app.approvals.service import ApprovalBindingMismatchError, ApprovalService, ApprovalTimedOutError
from app.approvals.workflows import ApprovalWorkflowRegistry
from app.audit.service import AuditService
from app.auth.identity import AgentIdentity, load_agents_configuration
from app.auth.permissions import PermissionEvaluator
from app.database.models import Base
from app.gateway.errors import GatewayErrorCode
from app.gateway.metadata import ToolMetadataRegistry
from app.gateway.servers import DownstreamServerRegistry
from app.gateway.service import MCPGatewayService
from app.policy.engine import PolicyEngine
from app.policy.models import PoliciesConfiguration, PolicyAction
from app.risk.models import RiskAssessment, RiskLevel
from app.security.evaluator import SecurityEvaluator
from app.security.models import ToolRequestContext
from app.simulation.models import SimulationRequest
from app.simulation.service import SimulationService
from app.workflows.models import WorkflowContextInput
from app.workflows.registry import WorkflowContextResolver
from evaluation.models import EvaluationResult, ScenarioResult
from evaluation.spy import DownstreamExecutionSpy, tool


class FakeClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def _agent(agent_id: str, role: str, environment: str = "development") -> AgentIdentity:
    return AgentIdentity(agent_id=agent_id, owner="evaluation", role=role, environment=environment)


def _error_code(outcome: Any) -> str | None:
    return outcome.error.code.value if outcome.error else None


def _scenario(
    scenario_id: str, category: str, expected_decision: str, actual_decision: str,
    expected_count: int, actual_count: int, expected_error: str | None = None,
    actual_error: str | None = None, detail: str = "",
) -> ScenarioResult:
    passed = (
        expected_decision == actual_decision
        and expected_count == actual_count
        and expected_error == actual_error
    )
    return ScenarioResult(
        scenario_id, category, passed, expected_decision, actual_decision,
        expected_count, actual_count, expected_error, actual_error, detail,
    )


def run_security_scenarios() -> EvaluationResult:
    """Run normal and adversarial paths against one in-memory gateway instance."""

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    clock = FakeClock()
    audit = AuditService(factory)
    agents = load_agents_configuration("config/agents.yaml")
    spy = DownstreamExecutionSpy({
        "normal-tools": [tool("tickets.search")],
        "sensitive-data": [tool("database.delete"), tool("secrets.read")],
        "messaging": [tool("external.send")],
    })
    approvals = ApprovalService(
        factory, ApprovalWorkflowRegistry.from_config_file("config/approval_workflows.yaml"), audit, clock
    )
    gateway = MCPGatewayService(
        servers=DownstreamServerRegistry.from_config_file("config/mcp_servers.yaml"),
        metadata=ToolMetadataRegistry.from_config_file("config/tool_metadata.yaml"),
        permissions=PermissionEvaluator(agents),
        security_evaluator=SecurityEvaluator.from_config_directory("config"),
        downstream_client=spy,  # type: ignore[arg-type]
        audit_service=audit,
        approval_service=approvals,
    )
    results: list[ScenarioResult] = []

    before = spy.call_count
    allowed = asyncio.run(gateway.call_tool(_agent("support-agent", "support"), "normal-tools.tickets.search", {"query": "status"}, "normal"))
    results.append(_scenario("normal-allowed-read", "normal", "ALLOW", "ALLOW" if allowed.error is None else "DENY", 1, spy.call_count - before))

    before = spy.call_count
    denied = asyncio.run(gateway.call_tool(_agent("support-agent", "support"), "sensitive-data.secrets.read", {}, "deny"))
    results.append(_scenario("permission-deny-zero-execution", "permissions", "DENY", "DENY" if denied.error else "ALLOW", 0, spy.call_count - before, GatewayErrorCode.PERMISSION_DENIED.value, _error_code(denied)))

    before = spy.call_count
    pending = asyncio.run(gateway.call_tool(_agent("admin-agent", "admin", "production"), "sensitive-data.database.delete", {"table": "temp"}, "approval"))
    results.append(_scenario("approval-required-zero-execution", "approval", "REQUIRE_APPROVAL", "REQUIRE_APPROVAL" if _error_code(pending) == GatewayErrorCode.APPROVAL_REQUIRED.value else "DENY", 0, spy.call_count - before, GatewayErrorCode.APPROVAL_REQUIRED.value, _error_code(pending)))

    approval_id = pending.error.approval_id if pending.error else ""
    clock.advance(901)
    approvals.get(approval_id)
    clock.advance(901)
    approvals.get(approval_id)
    before = spy.call_count
    exhausted = asyncio.run(gateway.execute_approved_action(_agent("admin-agent", "admin", "production"), approval_id))
    timeline = {event.event_type for event in audit.list_events(approval_id=approval_id)}
    results.append(_scenario("approval-chain-exhausted", "approval_escalation", "DENY", "DENY" if exhausted.error else "ALLOW", 0, spy.call_count - before, GatewayErrorCode.APPROVAL_TIMED_OUT.value, _error_code(exhausted), detail=",".join(sorted(timeline))))

    valid_pending = asyncio.run(gateway.call_tool(
        _agent("admin-agent", "admin", "production"), "sensitive-data.database.delete", {"table": "approved_temp"}, "valid-approval"
    ))
    valid_approval_id = valid_pending.error.approval_id if valid_pending.error else ""
    approvals.approve(valid_approval_id, ApproverIdentity(subject_id="system-owner-1", display_name="Owner", role="system_owner"))
    before = spy.call_count
    valid_execution = asyncio.run(gateway.execute_approved_action(_agent("admin-agent", "admin", "production"), valid_approval_id))
    results.append(_scenario("valid-approved-execution", "normal", "ALLOW", "ALLOW" if valid_execution.error is None else "DENY", 1, spy.call_count - before))
    before = spy.call_count
    replay = asyncio.run(gateway.execute_approved_action(_agent("admin-agent", "admin", "production"), valid_approval_id))
    results.append(_scenario("consumed-approval-replay", "replay", "DENY", "DENY" if replay.error else "ALLOW", 0, spy.call_count - before, GatewayErrorCode.APPROVAL_ALREADY_CONSUMED.value, _error_code(replay)))

    binding = ApprovalBinding.create(
        agent_id="admin-agent", session_id="binding", gateway_tool_name="messaging.external.send",
        downstream_server="messaging", downstream_tool_name="external.send",
        arguments={"destination": "security@company.com", "data": "incident summary"},
        destination="security@company.com", destination_type="email", environment="development",
        security_context={"risk_level": "HIGH"}, policy_id="high-risk-approval", policy_version=1,
    )
    bound = approvals.create(
        request_id="binding", session_id="binding", agent_id="admin-agent", gateway_tool_name="messaging.external.send",
        downstream_server="messaging", downstream_tool_name="external.send",
        arguments={"destination": "security@company.com", "data": "incident summary"}, risk_score=80,
        risk_level="HIGH", risk_factors=[], matched_policy="high-risk-needs-approval",
        workflow_id="default-high-risk-workflow", reason="Approval required.", binding=binding,
        policy_id="high-risk-approval", policy_version=1,
    )
    approvals.approve(bound.approval_id, ApproverIdentity(subject_id="security-admin-1", display_name="Admin", role="security_admin"))
    changed = binding.model_copy(update={"destination_fingerprint": "changed"})
    before = spy.call_count
    try:
        approvals.claim_execution(bound.approval_id, "admin-agent", binding=changed)
        code = None
    except ApprovalBindingMismatchError as error:
        code = error.code
    results.append(_scenario("binding-destination-switch", "binding", "DENY", "DENY" if code else "ALLOW", 0, spy.call_count - before, GatewayErrorCode.APPROVAL_DESTINATION_MISMATCH.value, code))

    resolver = WorkflowContextResolver.from_config_file("config/workflows.yaml")
    resolved = resolver.resolve(
        gateway_environment="production",
        declared=WorkflowContextInput(workflow_id="critical-production-change", environment="development", business_criticality="low", customer_impact=False),
    )
    results.append(_scenario("trusted-context-overrides-caller", "context_tampering", "DENY", "DENY" if resolved.environment == "production" and resolved.customer_impact else "ALLOW", 0, 0, detail=",".join(resolved.conflicts)))

    conflict_config = PoliciesConfiguration.model_validate({"policies": [
        {"id": "allow", "name": "allow", "description": "evaluation", "version": 1, "owner": "security", "review": {"last_reviewed_at": "2026-01-01", "review_interval_days": 90}, "change_reason": "evaluation", "priority": 10, "match": {"tool": "tickets.search"}, "action": "ALLOW", "reason": "allow"},
        {"id": "deny", "name": "deny", "description": "evaluation", "version": 1, "owner": "security", "review": {"last_reviewed_at": "2026-01-01", "review_interval_days": 90}, "change_reason": "evaluation", "priority": 10, "match": {"tool": "tickets.search"}, "action": "DENY", "reason": "deny"},
    ]})
    conflict = PolicyEngine(conflict_config).evaluate(
        ToolRequestContext(request_id="conflict", session_id="conflict", agent=_agent("support-agent", "support"), tool_name="tickets.search"),
        RiskAssessment(score=5, level=RiskLevel.LOW, factors=[]),
    )
    results.append(_scenario("equal-priority-policy-conflict", "policy_conflict", "DENY", conflict.decision.value, 0, 0, "POLICY_CONFLICT", conflict.error_code))

    simulation = SimulationService(SecurityEvaluator.from_config_directory("config"), agents, resolver)
    simulated = simulation.evaluate(SimulationRequest(tool_name="tickets.search"))
    results.append(_scenario("simulation-zero-execution", "simulation", "ALLOW", simulated.decision.value, 0, 0))
    development_update = simulation.evaluate(SimulationRequest(
        tool_name="database.update", is_write_operation=True,
        workflow_context=WorkflowContextInput(workflow_id="routine-maintenance"),
    ))
    production_bulk_update = simulation.evaluate(SimulationRequest(
        agent_id="production-admin", tool_name="database.update", is_write_operation=True,
        workflow_context=WorkflowContextInput(workflow_id="customer-data-maintenance", estimated_records_affected=5000),
    ))
    results.append(_scenario("same-tool-development-context", "simulation", "ALLOW", development_update.decision.value, 0, 0))
    results.append(_scenario("same-tool-production-bulk-context", "simulation", "REQUIRE_APPROVAL", production_bulk_update.decision.value, 0, 0))
    return EvaluationResult(results, {"python_version": platform.python_version()})


def write_reports(
    result: EvaluationResult, directory: Path = Path("reports"), benchmark: dict[str, Any] | None = None,
) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    payload = {"generated_at": datetime.now(timezone.utc).isoformat(), "commit": commit, "metrics": result.metrics(), "scenarios": [item.__dict__ for item in result.scenarios], "metadata": result.metadata, "benchmark": benchmark}
    json_path = directory / "v2-evaluation.json"
    json_path.write_text(json.dumps(payload, indent=2) + "\n")
    metrics = result.metrics()
    rows = "\n".join(f"| {item.scenario_id} | {item.category} | {'PASS' if item.passed else 'FAIL'} | {item.actual_execution_count} |" for item in result.scenarios)
    benchmark_summary = "Not measured in this report." if benchmark is None else json.dumps(benchmark, indent=2)
    markdown = f"# Gatekeeper MCP V2 evaluation\n\nGenerated: {payload['generated_at']}\n\nCommit evaluated: `{commit}`\n\nPython: `{payload['metadata']['python_version']}`\n\n## Summary\n\n- Scenarios: {metrics['total_scenarios']}\n- Correct decisions: {metrics['correct_decisions']}/{metrics['total_scenarios']}\n- Unauthorized downstream executions: {metrics['unauthorized_execution_successes']}\n- Replay successes: {metrics['replay_successes']}\n- Approval bypass successes: {metrics['approval_bypass_successes']}\n- Context-tampering successes: {metrics['context_tampering_successes']}\n- Binding mutations detected: {metrics['binding_mutations_detected']}/{metrics['binding_mutations_tested']}\n- Simulation downstream executions: {metrics['simulation_downstream_executions']}\n- Policy conflicts failed closed: {metrics['policy_conflicts_failed_closed']}/{metrics['policy_conflict_scenarios']}\n\n## Benchmark\n\n```json\n{benchmark_summary}\n```\n\n## Scenario results\n\n| Scenario | Category | Result | Downstream executions |\n| --- | --- | --- | ---: |\n{rows}\n\n## Known limitations\n\nThis deterministic evaluation does not prove resistance to prompt injection, malicious downstream-server internals, covert channels, compromised hosts or approver accounts, enterprise federation, or distributed consistency failures.\n"
    markdown_path = directory / "v2-evaluation.md"
    markdown_path.write_text(markdown)
    return markdown_path, json_path


def main() -> int:
    result = run_security_scenarios()
    for item in result.scenarios:
        print(f"{'PASS' if item.passed else 'FAIL'} {item.scenario_id}")
    print(json.dumps(result.metrics(), indent=2))
    return 0 if all(item.passed for item in result.scenarios) else 1


if __name__ == "__main__":
    raise SystemExit(main())
