"""Immutable policy-version snapshots and review health."""

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.binding import hash_canonical
from app.approvals.clock import Clock, UtcClock
from app.audit.service import AuditService
from app.database.models import PolicyVersionRecord
from app.policy.models import PoliciesConfiguration, PolicyRule, PolicyStatus


class PolicySummary(BaseModel):
    id: str
    name: str
    version: int
    owner: str
    status: PolicyStatus
    review_status: str
    last_reviewed_at: str
    next_review_due_at: str
    approval_workflow: str | None


class PolicyLifecycleService:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        configuration: PoliciesConfiguration,
        audit_service: AuditService | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._configuration = configuration
        self._audit = audit_service
        self._clock = clock or UtcClock()

    def synchronize(self) -> None:
        """Persist new immutable config versions; reject in-place mutation."""
        events: list[tuple[str, PolicyRule, dict[str, Any]]] = []
        with self._session_factory() as session:
            for policy in self._configuration.policies:
                snapshot = policy.model_dump(mode="json")
                snapshot_hash = hash_canonical(snapshot)
                record = session.scalar(
                    select(PolicyVersionRecord).where(
                        PolicyVersionRecord.policy_id == policy.id,
                        PolicyVersionRecord.version == policy.version,
                    )
                )
                if record is not None:
                    if record.snapshot_hash != snapshot_hash:
                        # Phase 3 added optional workflow matchers.  A policy that does not
                        # use one is semantically unchanged from its V2 Phase 2 snapshot.
                        # Accept only that narrow, additive compatibility case.
                        legacy_snapshot = self._without_empty_workflow_matchers(snapshot)
                        if record.snapshot_hash != hash_canonical(legacy_snapshot):
                            raise ValueError(
                                f"Policy {policy.id} version {policy.version} changed without a version increment."
                            )
                    continue
                has_previous_version = session.scalar(
                    select(PolicyVersionRecord.id).where(PolicyVersionRecord.policy_id == policy.id)
                ) is not None
                record = PolicyVersionRecord(
                    policy_id=policy.id,
                    version=policy.version,
                    name=policy.name,
                    owner=policy.owner,
                    status=policy.status.value,
                    change_reason=policy.change_reason,
                    snapshot=snapshot,
                    snapshot_hash=snapshot_hash,
                    activated_at=self._now() if policy.status is PolicyStatus.ACTIVE else None,
                )
                session.add(record)
                session.flush()
                events.append((
                    "POLICY_UPDATED" if has_previous_version else "POLICY_CREATED",
                    policy,
                    {"policy_id": policy.id, "version": policy.version, "reason": policy.change_reason},
                ))
                if policy.status is PolicyStatus.ACTIVE:
                    events.append(("POLICY_ACTIVATED", policy, {"policy_id": policy.id, "version": policy.version}))
            session.commit()
        for event_type, policy, metadata in events:
            self._audit_event(event_type, policy, metadata)

    def list(self, *, status: PolicyStatus | None = None, owner: str | None = None, review_status: str | None = None) -> list[PolicySummary]:
        summaries = [self._summary(policy) for policy in self._configuration.policies]
        if status is not None:
            summaries = [item for item in summaries if item.status is status]
        if owner is not None:
            summaries = [item for item in summaries if item.owner == owner]
        if review_status is not None:
            summaries = [item for item in summaries if item.review_status == review_status]
        return summaries

    def get(self, policy_id: str) -> PolicySummary:
        for policy in self._configuration.policies:
            if policy.id == policy_id:
                return self._summary(policy)
        raise LookupError(policy_id)

    def history(self, policy_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            records = session.scalars(
                select(PolicyVersionRecord)
                .where(PolicyVersionRecord.policy_id == policy_id)
                .order_by(PolicyVersionRecord.version)
            ).all()
            return [
                {
                    "policy_id": record.policy_id,
                    "version": record.version,
                    "status": record.status,
                    "owner": record.owner,
                    "change_reason": record.change_reason,
                    "created_at": record.created_at,
                    "activated_at": record.activated_at,
                    "snapshot": record.snapshot,
                }
                for record in records
            ]

    def _summary(self, policy: PolicyRule) -> PolicySummary:
        stale = self._now().date() > policy.review.next_review_due_at
        if stale:
            self._mark_stale_once(policy)
        return PolicySummary(
            id=policy.id,
            name=policy.name,
            version=policy.version,
            owner=policy.owner,
            status=policy.status,
            review_status="STALE" if stale else "CURRENT",
            last_reviewed_at=policy.review.last_reviewed_at.isoformat(),
            next_review_due_at=policy.review.next_review_due_at.isoformat(),
            approval_workflow=policy.approval_workflow,
        )

    def _mark_stale_once(self, policy: PolicyRule) -> None:
        with self._session_factory() as session:
            record = session.scalar(
                select(PolicyVersionRecord).where(
                    PolicyVersionRecord.policy_id == policy.id,
                    PolicyVersionRecord.version == policy.version,
                )
            )
            if record is None or record.stale_reported_at is not None:
                return
            record.stale_reported_at = self._now()
            session.commit()
        self._audit_event(
            "POLICY_MARKED_STALE",
            policy,
            {"policy_id": policy.id, "version": policy.version, "review_due_at": policy.review.next_review_due_at.isoformat()},
        )

    def _audit_event(self, event_type: str, policy: PolicyRule, metadata: dict[str, Any]) -> None:
        if self._audit is not None:
            self._audit.record(event_type, metadata={"actor": "system", "actor_role": "system", **metadata})

    def _now(self) -> datetime:
        value = self._clock.now()
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    @staticmethod
    def _without_empty_workflow_matchers(snapshot: dict[str, Any]) -> dict[str, Any]:
        """Return the exact pre-Phase-3 representation for legacy snapshots only."""

        copied = {**snapshot, "match": dict(snapshot["match"])}
        for field in (
            "workflow_id", "business_criticality", "customer_impact",
            "minimum_records_affected", "after_hours", "emergency", "required_tags",
        ):
            if copied["match"].get(field) in (None, []):
                copied["match"].pop(field, None)
        return copied
