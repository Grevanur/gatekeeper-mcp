"""Measure Gatekeeper's in-process deterministic evaluation path only."""

import argparse
import json
import logging
from statistics import mean, median
from time import perf_counter_ns

from app.auth.identity import AgentIdentity
from app.security.evaluator import SecurityEvaluator
from app.security.models import ToolRequestContext


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))]


def benchmark(iterations: int = 1000) -> dict[str, object]:
    evaluator = SecurityEvaluator.from_config_directory("config")
    context = ToolRequestContext(
        request_id="benchmark", session_id="benchmark",
        agent=AgentIdentity(agent_id="support-agent", owner="benchmark", role="support", environment="development"),
        tool_name="tickets.search",
    )
    logging.getLogger("app.security.evaluator").setLevel(logging.CRITICAL)
    baseline_samples: list[float] = []
    samples: list[float] = []
    for _ in range(iterations):
        baseline_started = perf_counter_ns()
        _ = context.tool_name  # Baseline direct local dispatch preparation; no network involved.
        baseline_samples.append((perf_counter_ns() - baseline_started) / 1_000_000)
        started = perf_counter_ns()
        evaluator.evaluate(context)
        samples.append((perf_counter_ns() - started) / 1_000_000)
    return {
        "iterations": iterations,
        "measurement": "in-process direct-dispatch preparation compared with deterministic security evaluation; no network or downstream tool latency included",
        "baseline_direct_dispatch_ms": {
            "mean": round(mean(baseline_samples), 4),
            "median": round(median(baseline_samples), 4),
            "p95": round(_percentile(baseline_samples, 0.95), 4),
        },
        "security_evaluation_ms": {
            "mean": round(mean(samples), 4),
            "median": round(median(samples), 4),
            "p95": round(_percentile(samples, 0.95), 4),
            "p99": round(_percentile(samples, 0.99), 4),
        },
        "added_security_overhead_ms": round(mean(samples) - mean(baseline_samples), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000)
    arguments = parser.parse_args()
    result = benchmark(arguments.iterations)
    print("Gatekeeper MCP V2 Benchmark")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
