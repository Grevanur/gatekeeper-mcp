# Security invariants

The V2 release gate treats these as testable requirements, not aspirational claims.

1. A `DENY` decision forwards zero downstream calls.
2. `REQUIRE_APPROVAL` forwards zero downstream calls until a valid approval is claimed.
3. Timed-out or expired approvals forward zero downstream calls.
4. An approved exact request executes at most once.
5. A changed destination invalidates the original approval.
6. Changed arguments invalidate the original approval.
7. A changed tool invalidates the original approval.
8. Changed environment or security context requires a fresh decision.
9. Caller-declared workflow context cannot downgrade trusted gateway or registry context.
10. Simulation forwards zero downstream calls.
11. Equal-priority conflicting policies fail closed.
12. An unauthorized approver cannot approve.
13. Break-glass requires an authorized role, a sufficiently specific reason, and a valid TTL.
14. A replayed approval cannot execute a second time.

The existing approval, binding, session, policy, and Phase 3 test modules exercise the lifecycle-specific invariants. `tests/test_v2_security_evaluation.py` and `python -m evaluation.runner` add cross-component downstream-count verification.
