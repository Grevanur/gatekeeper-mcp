# Policy simulation

`POST /simulate/evaluate` runs the normal identity, permission, risk, and policy pipeline against a proposed workflow context. `POST /simulate/compare` evaluates two contexts and reports the safe context-field, risk-factor, policy, and decision differences. A comparison may include a complete `candidate_policies` configuration; that configuration is used only by an isolated evaluator and is never activated or persisted.

Both endpoints are admin-only and dry-run only. The simulation service has no downstream MCP client, so `downstream_executed` is always `false`; no tools, approvals, sessions, or audit records are created.

Declared regression scenarios live in `config/policy_scenarios.yaml`. Run them with:

```bash
.venv/bin/python scripts/run_v2_policy_regression_demo.py
```

Treat a regression failure as unsafe to activate. Candidate policy changes should be evaluated against the declared scenarios before their version is activated.
