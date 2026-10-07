# Approval governance

Human approval is not a permanent bypass. Every Gatekeeper approval is role-bound, request-bound, time-bound, auditable, and single-use.

```text
PENDING_PRIMARY
  |-- primary approval -> APPROVED -> EXECUTING -> EXECUTED
  |-- primary timeout -> PENDING_FALLBACK
  |    |-- fallback approval -> APPROVED -> EXECUTING -> EXECUTED
  |    `-- fallback timeout -> TIMED_OUT (deny)
  `-- authorized break-glass -> BREAK_GLASS_APPROVED -> EXECUTING -> EXECUTED
                                       `-- TTL expiry -> EXPIRED
```

Workflows are defined in `config/approval_workflows.yaml` and referenced by `REQUIRE_APPROVAL` policies. Primary and fallback approvers are authorized by their configured human approver role, not by possession of a generic admin token.

Timeout processing is lazy: reads, list operations, approval decisions, and execution claims advance due state transitions. A final timeout is terminal and fail-closed; it never forwards the action.

Break-glass is exceptional. A configured emergency role must provide a meaningful justification, receives only the configured short TTL, and can authorize the original bound request once. It does not bypass the gateway's original security decision, agent/session binding, or argument hash.

The audit timeline is available through `GET /approvals/{approval_id}/timeline`. It records creation, stage transitions, role decisions, timeout denial, break-glass actions, execution, and replay blocking. Basic redaction is applied to structured audit metadata; users must not include secrets in free-text emergency justifications.

For existing local development databases, startup applies an additive SQLite migration for the governance columns. A fresh development database needs no manual migration.
