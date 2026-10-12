"""Machine-readable evaluation results."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    category: str
    passed: bool
    expected_decision: str
    actual_decision: str
    expected_execution_count: int
    actual_execution_count: int
    expected_error_code: str | None = None
    actual_error_code: str | None = None
    detail: str = ""


@dataclass
class EvaluationResult:
    scenarios: list[ScenarioResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def metrics(self) -> dict[str, int | float]:
        total = len(self.scenarios)
        correct = sum(item.passed for item in self.scenarios)
        adversarial = [item for item in self.scenarios if item.category != "normal"]
        unauthorized = [item for item in adversarial if item.expected_execution_count == 0]
        categories = lambda value: [item for item in self.scenarios if item.category == value]
        return {
            "total_scenarios": total,
            "normal_scenarios": len(categories("normal")),
            "adversarial_scenarios": len(adversarial),
            "correct_decisions": correct,
            "incorrect_decisions": total - correct,
            "decision_correctness_rate": (correct / total) if total else 0.0,
            "unauthorized_execution_attempts": len(unauthorized),
            "unauthorized_execution_successes": sum(item.actual_execution_count > 0 for item in unauthorized),
            "approval_bypass_attempts": len(categories("approval")) + len(categories("approval_escalation")),
            "approval_bypass_successes": sum(item.actual_execution_count > 0 for item in categories("approval") + categories("approval_escalation")),
            "replay_attempts": len(categories("replay")),
            "replay_successes": sum(item.actual_execution_count > 0 for item in categories("replay")),
            "context_tampering_attempts": len(categories("context_tampering")),
            "context_tampering_successes": sum(item.actual_execution_count > 0 for item in categories("context_tampering")),
            "binding_mutations_tested": len(categories("binding")),
            "binding_mutations_detected": sum(item.passed for item in categories("binding")),
            "simulation_scenarios": len(categories("simulation")),
            "simulation_downstream_executions": sum(item.actual_execution_count for item in categories("simulation")),
            "policy_conflict_scenarios": len(categories("policy_conflict")),
            "policy_conflicts_failed_closed": sum(item.passed for item in categories("policy_conflict")),
        }
