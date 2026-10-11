"""Show that one tool receives different deterministic decisions by context."""

from app.auth.identity import load_agents_configuration
from app.security.evaluator import SecurityEvaluator
from app.simulation.models import SimulationRequest
from app.simulation.service import SimulationService
from app.workflows.models import WorkflowContextInput
from app.workflows.registry import WorkflowContextResolver


def service() -> SimulationService:
    return SimulationService(
        SecurityEvaluator.from_config_directory("config"),
        load_agents_configuration("config/agents.yaml"),
        WorkflowContextResolver.from_config_file("config/workflows.yaml"),
    )


def main() -> None:
    scenarios = (
        ("A", SimulationRequest(tool_name="database.update", is_write_operation=True,
            workflow_context=WorkflowContextInput(workflow_id="routine-maintenance"))),
        ("B", SimulationRequest(agent_id="production-admin", tool_name="database.update", is_write_operation=True,
            workflow_context=WorkflowContextInput(workflow_id="customer-data-maintenance", estimated_records_affected=5000))),
        ("C", SimulationRequest(agent_id="production-admin", tool_name="database.update", is_write_operation=True,
            workflow_context=WorkflowContextInput(workflow_id="critical-production-change", after_hours=True, estimated_records_affected=100000))),
    )
    for label, request in scenarios:
        result = service().evaluate(request)
        print(f"Scenario {label}: {result.risk.score} / {result.risk.level.value} -> {result.decision.value}")
    print("Downstream execution: 0")


if __name__ == "__main__":
    main()
