# Exact approval binding

Human approval applies to the exact action reviewed, not to a future category of actions. Gatekeeper records a canonical SHA-256 argument hash, gateway and downstream tool identity, normalized destination fingerprint, agent and session, environment, stable security-context fingerprint, and the policy ID/version that produced the decision.

Mapping keys are recursively sorted before hashing; list order is preserved. A destination value is fingerprinted rather than returned in approval responses.

Before one-time execution, Gatekeeper compares the requested action to the binding. A tool, destination, argument, environment, or security-context mismatch is denied before the downstream server is called. The structured response sets fresh-decision-required and returns safe field names only.

Approvals remain tied to the policy version that created them until expiry. A later policy configuration version never silently reinterprets an existing approval.
