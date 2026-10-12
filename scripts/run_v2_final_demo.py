"""Short V2 release demonstration using the evaluated scenario harness."""

from evaluation.runner import run_security_scenarios


def main() -> None:
    selected = {
        "same-tool-development-context": "Scenario 1: database update in development context",
        "same-tool-production-bulk-context": "Scenario 1: same database update in production bulk context",
        "approval-chain-exhausted": "Scenario 2: approval chain exhausted",
        "binding-destination-switch": "Scenario 3: exact approval destination binding",
        "simulation-zero-execution": "Scenario 4: policy simulation",
    }
    result = run_security_scenarios()
    print("=" * 58)
    print("GATEKEEPER MCP V2 SECURITY EVALUATION")
    print("=" * 58)
    for item in result.scenarios:
        if item.scenario_id in selected:
            print(f"\n{selected[item.scenario_id]}")
            print(f"Expected: {item.expected_decision}")
            print(f"Actual: {item.actual_decision}")
            print(f"Downstream executed: {'YES' if item.actual_execution_count else 'NO'}")
            print("PASS" if item.passed else "FAIL")
    metrics = result.metrics()
    print(f"\nEvaluation summary: {metrics['correct_decisions']}/{metrics['total_scenarios']} scenarios passed; unauthorized downstream executions: {metrics['unauthorized_execution_successes']}")


if __name__ == "__main__":
    main()
