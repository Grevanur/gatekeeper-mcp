# Policy lifecycle

Each policy has a stable ID, owner, version, status, review date, interval, and change reason. Only ACTIVE policies enforce. DRAFT, DEPRECATED, and DISABLED policies remain visible in configuration and history but do not match requests.

Startup snapshots each unseen policy ID/version into SQLite. Reusing a version number with changed content fails startup; policy logic must receive a new version. The history API exposes immutable prior snapshots.

An overdue review produces STALE health status and one POLICY_MARKED_STALE audit event. Staleness is a governance signal, not an automatic disabling mechanism.

Policy changes are configuration-driven in this phase. Pending approvals intentionally remain bound to their original policy version until their configured expiry; revocation is deferred to a later phase.
