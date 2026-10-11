"""Run declared policy regression scenarios without any downstream execution."""

from pathlib import Path

from app.configuration import load_yaml_mapping
from app.simulation.models import PolicyRegressionConfiguration
from run_v2_workflow_context_demo import service


def main() -> None:
    scenarios = PolicyRegressionConfiguration.model_validate(
        load_yaml_mapping(Path("config/policy_scenarios.yaml"))
    )
    results = service().run_regressions(scenarios)
    passed = sum(result.passed for result in results)
    print(f"Running {len(results)} policy scenarios...")
    print(f"{passed} PASS")
    for result in results:
        if not result.passed:
            print(f"FAIL {result.scenario_id}: expected {result.expected.value}, got {result.actual.value}")
    print("SAFE TO ACTIVATE" if passed == len(results) else "NOT SAFE TO ACTIVATE")


if __name__ == "__main__":
    main()
