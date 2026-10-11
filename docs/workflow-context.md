# Workflow context

Gatekeeper evaluates a tool call in the context of the work being performed, not only its tool name. A normalized workflow context includes the gateway-derived environment, registered workflow, business criticality, customer impact, estimated records affected, after-hours status, emergency flag, and tags.

`config/workflows.yaml` is the trusted registry. The authenticated agent supplies the environment. A caller may declare additional context, but it cannot silently weaken a trusted value: environment conflicts are ignored in favor of the gateway identity, criticality uses the higher value, customer impact is additive, and registered after-hours calculations use the configured workflow time zone. Conflicts are surfaced as field names in the simulation result; raw request arguments are not included.

Workflow context changes deterministic risk factors. High or critical work, customer impact, bulk and large blast radius, after-hours changes, and emergency changes increase risk. An emergency label never grants an allow decision or bypasses policy.

Policies can match workflow ID, criticality, customer impact, minimum records affected, after-hours state, emergency state, and required tags. Equal-priority conflicting policies remain fail-closed. The same tool can therefore be allowed in routine development maintenance, require approval for a bulk production change, and be denied for a critical after-hours production change.

The live MCP gateway derives context from trusted gateway state. It does not accept a caller-provided environment override.
