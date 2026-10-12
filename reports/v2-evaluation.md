# Gatekeeper MCP V2 evaluation

Generated: 2026-10-12T01:00:34.856790+00:00

Commit evaluated: `d31c5875258951362e4bbbcdbdf474e48930e9e8`

Python: `3.14.4`

## Summary

- Scenarios: 12
- Correct decisions: 12/12
- Unauthorized downstream executions: 0
- Replay successes: 0
- Approval bypass successes: 0
- Context-tampering successes: 0
- Binding mutations detected: 1/1
- Simulation downstream executions: 0
- Policy conflicts failed closed: 1/1

## Benchmark

```json
{
  "iterations": 1000,
  "measurement": "in-process direct-dispatch preparation compared with deterministic security evaluation; no network or downstream tool latency included",
  "baseline_direct_dispatch_ms": {
    "mean": 0.0,
    "median": 0.0,
    "p95": 0.0001
  },
  "security_evaluation_ms": {
    "mean": 0.0065,
    "median": 0.0064,
    "p95": 0.007,
    "p99": 0.0075
  },
  "added_security_overhead_ms": 0.0065
}
```

## Scenario results

| Scenario | Category | Result | Downstream executions |
| --- | --- | --- | ---: |
| normal-allowed-read | normal | PASS | 1 |
| permission-deny-zero-execution | permissions | PASS | 0 |
| approval-required-zero-execution | approval | PASS | 0 |
| approval-chain-exhausted | approval_escalation | PASS | 0 |
| valid-approved-execution | normal | PASS | 1 |
| consumed-approval-replay | replay | PASS | 0 |
| binding-destination-switch | binding | PASS | 0 |
| trusted-context-overrides-caller | context_tampering | PASS | 0 |
| equal-priority-policy-conflict | policy_conflict | PASS | 0 |
| simulation-zero-execution | simulation | PASS | 0 |
| same-tool-development-context | simulation | PASS | 0 |
| same-tool-production-bulk-context | simulation | PASS | 0 |

## Known limitations

This deterministic evaluation does not prove resistance to prompt injection, malicious downstream-server internals, covert channels, compromised hosts or approver accounts, enterprise federation, or distributed consistency failures.
