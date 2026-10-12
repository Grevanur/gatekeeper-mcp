# Gatekeeper MCP v2.0.0 draft release notes

## Highlights

- Approval governance with primary/fallback escalation, terminal timeout, and controlled break-glass.
- Exact approval binding for arguments, destinations, tools, environments, and security context.
- Policy ownership, version history, stale-policy visibility, workflow context, and dry-run policy simulation.
- A reusable security scenario harness, formal invariants, deterministic benchmark, and generated evaluation report.

## Validation

Run `python scripts/verify_v2_release.py` to generate the current test, scenario, and benchmark evidence. The generated report is the authoritative source for counts.

## Known limitations

V2 does not claim to solve prompt injection, malicious downstream-server internals, covert channels, compromised gateway hosts or approver accounts, enterprise identity federation, or distributed multi-node consistency.
