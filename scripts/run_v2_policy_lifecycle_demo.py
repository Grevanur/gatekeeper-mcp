"""Demonstrate immutable policy versions and stale review visibility."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.audit.service import AuditService
from app.database.models import Base
from app.policy.lifecycle import PolicyLifecycleService
from app.policy.models import PoliciesConfiguration


class DemoClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.value


def config(version: int, reason: str) -> PoliciesConfiguration:
    return PoliciesConfiguration.model_validate({"policies": [{
        "id": "prod-delete-approval", "name": "Production delete approval",
        "description": "Production destructive actions.", "version": version, "owner": "platform-security",
        "status": "ACTIVE", "review": {"last_reviewed_at": "2026-01-01", "review_interval_days": 90},
        "change_reason": reason, "priority": 10, "match": {}, "action": "REQUIRE_APPROVAL",
        "approval_workflow": "production-destructive-workflow", "reason": "Approval required.",
    }]})


if __name__ == "__main__":
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    clock = DemoClock()
    first = PolicyLifecycleService(factory, config(3, "Initial production governance."), AuditService(factory), clock)
    first.synchronize()
    clock.value += timedelta(days=91)
    print("GATEKEEPER MCP — POLICY LIFECYCLE")
    print("Policy: prod-delete-approval")
    print("Version: 3")
    print("Owner: platform-security")
    print("Review status:", first.get("prod-delete-approval").review_status)
    updated = PolicyLifecycleService(factory, config(4, "Added fallback security approver."), AuditService(factory), clock)
    updated.synchronize()
    print("Version: 4")
    print("Status: ACTIVE")
    print("Audit history: v3 -> v4")
