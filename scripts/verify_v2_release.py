"""CI-friendly V2 release gate: tests, security scenarios, benchmark, and reports."""

import subprocess
import sys

from evaluation.runner import run_security_scenarios, write_reports
from scripts.benchmark_gateway import benchmark


def main() -> int:
    tests = subprocess.run([sys.executable, "-m", "pytest", "-q"], check=False)
    if tests.returncode != 0:
        return tests.returncode
    evaluation = run_security_scenarios()
    if not all(item.passed for item in evaluation.scenarios):
        return 1
    markdown, machine = write_reports(evaluation, benchmark=benchmark(1000))
    print(f"Release gate passed. Reports: {markdown}, {machine}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
