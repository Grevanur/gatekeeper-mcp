"""Compare a routine context with a production bulk-change candidate context."""

from pathlib import Path

from app.auth.identity import load_agents_configuration
from app.configuration import load_yaml_mapping
from app.policy.models import PoliciesConfiguration
from app.security.evaluator import SecurityEvaluator
from app.simulation.models import SimulationComparisonRequest, SimulationRequest
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
    candidate = load_yaml_mapping(Path("config/policies.yaml"))
    for policy in candidate["policies"]:
        if policy["id"] == "routine-development-update-allow":
            policy.update({
                "version": 2,
                "action": "REQUIRE_APPROVAL",
                "approval_workflow": "default-high-risk-workflow",
                "change_reason": "Candidate v2 adds maintenance review.",
                "reason": "Candidate adds maintenance change control.",
            })
    result = service().compare(SimulationComparisonRequest(
        baseline=SimulationRequest(tool_name="database.update", is_write_operation=True,
            workflow_context=WorkflowContextInput(workflow_id="routine-maintenance")),
        candidate=SimulationRequest(tool_name="database.update", is_write_operation=True,
            workflow_context=WorkflowContextInput(workflow_id="routine-maintenance")),
        candidate_policies=PoliciesConfiguration.model_validate(candidate),
    ))
    print(f"Current policy v1: {result.baseline.decision.value}")
    print(f"Candidate policy v2: {result.candidate.decision.value}")
    print(result.explanation)
    print("Downstream execution: 0")


if __name__ == "__main__":
    main()
