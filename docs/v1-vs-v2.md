# V1 and V2 progression

| Capability | V1 | V2 |
| --- | --- | --- |
| Deterministic risk and policy decisions | Yes | Yes |
| Stateful sensitive-session protection | Yes | Yes |
| Append-only audit trail | Yes | Yes, with approval governance metadata |
| Human approval | Basic | Primary/fallback escalation, timeout, and break-glass governance |
| Approval replay prevention | Yes | Exact request, destination, tool, environment, and security-context binding |
| Policy ownership and version history | No | Yes, including stale-policy detection |
| Workflow-aware risk | No | Yes, including business criticality and blast radius |
| Candidate policy evaluation | No | Isolated dry-run comparison and regression scenarios |
| Release evaluation | Basic tests/demos | Scenario harness, invariants, benchmark, and generated report |

V2 preserves the deterministic V1 enforcement model while adding governance and verification around high-impact decisions.
