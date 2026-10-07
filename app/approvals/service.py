"""Approval workflows with staged, role-bound, fail-closed governance."""

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.approvals.authorization import can_approve
from app.approvals.clock import Clock, UtcClock
from app.approvals.identity import ApproverIdentity
from app.approvals.models import ApprovalRequest, ApprovalStatus, ExecutionClaim
from app.approvals.workflows import ApprovalWorkflow, ApprovalWorkflowRegistry
from app.audit.redaction import sanitize_arguments, sanitize_free_text
from app.audit.service import AuditService
from app.database.models import ApprovalRequestRecord


class ApprovalNotFoundError(LookupError):
    pass


class ApprovalDeniedError(PermissionError):
    pass


class ApprovalExpiredError(PermissionError):
    pass


class ApprovalTimedOutError(PermissionError):
    pass


class ApprovalAlreadyConsumedError(PermissionError):
    pass


class ApprovalArgumentMismatchError(PermissionError):
    pass


def hash_arguments(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


class ApprovalService:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        workflows: ApprovalWorkflowRegistry,
        audit_service: AuditService | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._workflows = workflows
        self._audit = audit_service
        self._clock = clock or UtcClock()

    def create(
        self,
        *,
        request_id: str,
        session_id: str,
        agent_id: str,
        gateway_tool_name: str,
        downstream_server: str,
        downstream_tool_name: str,
        arguments: dict[str, Any],
        risk_score: int,
        risk_level: str,
        risk_factors: list[dict[str, Any]],
        matched_policy: str | None,
        workflow_id: str,
        reason: str,
    ) -> ApprovalRequest:
        workflow = self._workflows.get(workflow_id)
        now = self._now()
        primary_deadline = now + timedelta(seconds=workflow.primary.timeout_seconds)
        final_deadline = primary_deadline + timedelta(seconds=workflow.fallback.timeout_seconds if workflow.fallback else 0)
        record = ApprovalRequestRecord(
            approval_id=f"apr_{uuid4().hex}",
            created_at=now,
            expires_at=final_deadline,
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
            gateway_tool_name=gateway_tool_name,
            downstream_server=downstream_server,
            downstream_tool_name=downstream_tool_name,
            sanitized_arguments=sanitize_arguments(arguments),
            original_arguments=arguments,
            argument_hash=hash_arguments(arguments),
            risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            matched_policy=matched_policy,
            reason=reason,
            status=ApprovalStatus.PENDING_PRIMARY.value,
            execution_status="PENDING_APPROVAL",
            workflow_id=workflow_id,
            stage="PRIMARY",
            primary_expires_at=primary_deadline,
        )
        with self._session_factory() as session:
            session.add(record)
            session.commit()
            session.refresh(record)
        self._audit_event("APPROVAL_CREATED", record, "system", "system")
        self._audit_event("APPROVAL_PRIMARY_PENDING", record, "system", "system")
        return self._to_model(record, workflow_id, workflow)

    def get(self, approval_id: str) -> ApprovalRequest:
        with self._session_factory() as session:
            record = self._require_record(session, approval_id)
            self.advance_approval_state_if_needed(session, record)
            return self._to_model(record)

    def list(self) -> list[ApprovalRequest]:
        with self._session_factory() as session:
            records = session.scalars(select(ApprovalRequestRecord).order_by(ApprovalRequestRecord.created_at.desc())).all()
            for record in records:
                self.advance_approval_state_if_needed(session, record)
            return [self._to_model(record) for record in records]

    def approve(self, approval_id: str, approver: ApproverIdentity) -> ApprovalRequest:
        with self._session_factory() as session:
            record = self._require_record(session, approval_id)
            self.advance_approval_state_if_needed(session, record)
            workflow = self._workflow(record)
            if record.status not in {ApprovalStatus.PENDING_PRIMARY.value, ApprovalStatus.PENDING_FALLBACK.value}:
                raise ApprovalDeniedError("Approval is not actionable.")
            authority = can_approve(approver, record.agent_id, workflow, record.stage)
            if not authority.allowed:
                self._audit_event(self._stage_event(record.stage, "DENIED"), record, approver.subject_id, approver.role, {"reason": authority.reason})
                raise ApprovalDeniedError(authority.reason)
            record.status = ApprovalStatus.APPROVED.value
            record.approved_by = approver.subject_id
            record.approved_at = self._now()
            session.commit()
            session.refresh(record)
        self._audit_event(self._stage_event(record.stage, "APPROVED"), record, approver.subject_id, approver.role)
        return self._to_model(record)

    def deny(self, approval_id: str, approver: ApproverIdentity) -> ApprovalRequest:
        with self._session_factory() as session:
            record = self._require_record(session, approval_id)
            self.advance_approval_state_if_needed(session, record)
            workflow = self._workflow(record)
            if record.status not in {ApprovalStatus.PENDING_PRIMARY.value, ApprovalStatus.PENDING_FALLBACK.value}:
                raise ApprovalDeniedError("Approval is not actionable.")
            authority = can_approve(approver, record.agent_id, workflow, record.stage)
            if not authority.allowed:
                self._audit_event(self._stage_event(record.stage, "DENIED"), record, approver.subject_id, approver.role, {"reason": authority.reason})
                raise ApprovalDeniedError(authority.reason)
            record.status = ApprovalStatus.DENIED.value
            record.denied_by = approver.subject_id
            record.denied_at = self._now()
            record.execution_status = "BLOCKED"
            session.commit()
            session.refresh(record)
        self._audit_event(self._stage_event(record.stage, "DENIED"), record, approver.subject_id, approver.role)
        return self._to_model(record)

    def break_glass(self, approval_id: str, approver: ApproverIdentity, reason: str) -> ApprovalRequest:
        reason = sanitize_free_text(reason.strip())
        with self._session_factory() as session:
            record = self._require_record(session, approval_id)
            self.advance_approval_state_if_needed(session, record)
            workflow = self._workflow(record)
            self._audit_event("BREAK_GLASS_REQUESTED", record, approver.subject_id, approver.role, {"reason": reason})
            denial = self._break_glass_denial(record, workflow, approver, reason)
            if denial:
                self._audit_event("BREAK_GLASS_DENIED", record, approver.subject_id, approver.role, {"reason": denial})
                raise ApprovalDeniedError(denial)
            record.status = ApprovalStatus.BREAK_GLASS_APPROVED.value
            record.stage = "BREAK_GLASS"
            record.break_glass_by = approver.subject_id
            record.break_glass_reason = reason
            record.break_glass_expires_at = self._now() + timedelta(seconds=workflow.break_glass.ttl_seconds)
            session.commit()
            session.refresh(record)
        self._audit_event("BREAK_GLASS_GRANTED", record, approver.subject_id, approver.role, {"reason": reason})
        return self._to_model(record)

    def claim_execution(self, approval_id: str, agent_id: str, arguments: dict[str, Any] | None = None) -> ExecutionClaim:
        with self._session_factory() as session:
            record = self._require_record(session, approval_id)
            self.advance_approval_state_if_needed(session, record)
            if record.agent_id != agent_id:
                self._blocked_replay(record, agent_id, "Agent binding mismatch.")
                raise ApprovalDeniedError("Approval is bound to a different agent.")
            if record.status == ApprovalStatus.TIMED_OUT.value:
                raise ApprovalTimedOutError("Approval workflow timed out.")
            if record.status == ApprovalStatus.EXPIRED.value:
                raise ApprovalExpiredError("Approval has expired.")
            if arguments is not None and hash_arguments(arguments) != record.argument_hash:
                self._blocked_replay(record, agent_id, "Argument binding mismatch.")
                raise ApprovalArgumentMismatchError("Arguments do not match the approved request.")
            permitted = {ApprovalStatus.APPROVED.value, ApprovalStatus.BREAK_GLASS_APPROVED.value}
            if record.status not in permitted:
                self._blocked_replay(record, agent_id, "Approval is not executable.")
                raise ApprovalAlreadyConsumedError("Approval is not available for execution.")
            claimed = session.execute(
                update(ApprovalRequestRecord)
                .where(ApprovalRequestRecord.id == record.id, ApprovalRequestRecord.status.in_(permitted))
                .values(status=ApprovalStatus.EXECUTING.value, execution_status="EXECUTING")
            )
            if claimed.rowcount != 1:
                raise ApprovalAlreadyConsumedError("Approval was already claimed for execution.")
            session.commit()
            session.refresh(record)
            return ExecutionClaim(approval=self._to_model(record), original_arguments=record.original_arguments)

    def complete_execution(self, approval_id: str, success: bool, actor_id: str) -> ApprovalRequest:
        with self._session_factory() as session:
            record = self._require_record(session, approval_id)
            if record.status != ApprovalStatus.EXECUTING.value:
                raise ApprovalAlreadyConsumedError("Approval was not claimed for execution.")
            record.status = ApprovalStatus.EXECUTED.value if success else ApprovalStatus.FAILED.value
            record.execution_status = "EXECUTED" if success else "DOWNSTREAM_FAILED"
            record.executed_at = self._now()
            session.commit()
            session.refresh(record)
        self._audit_event("APPROVAL_EXECUTED" if success else "APPROVAL_FAILED", record, actor_id, "agent")
        if success and record.break_glass_by:
            self._audit_event("BREAK_GLASS_EXECUTED", record, actor_id, "agent")
        return self._to_model(record)

    def advance_approval_state_if_needed(self, session: Session, record: ApprovalRequestRecord) -> bool:
        """Apply every due timeout transition once, lazily and fail closed."""
        self._upgrade_legacy_record(session, record)
        workflow = self._workflow(record)
        now = self._now()
        if record.status == ApprovalStatus.PENDING_PRIMARY.value and self._due(record.primary_expires_at, now):
            if workflow.fallback:
                record.status = ApprovalStatus.PENDING_FALLBACK.value
                record.stage = "FALLBACK"
                record.fallback_started_at = now
                record.fallback_expires_at = now + timedelta(seconds=workflow.fallback.timeout_seconds)
                session.commit()
                session.refresh(record)
                self._audit_event("APPROVAL_ESCALATED", record, "system", "system", {"from_stage": "primary", "to_stage": "fallback", "reason": "primary_timeout"})
                return True
            self._time_out(session, record)
            return True
        if record.status == ApprovalStatus.PENDING_FALLBACK.value and self._due(record.fallback_expires_at, now):
            self._time_out(session, record)
            return True
        if record.status == ApprovalStatus.BREAK_GLASS_APPROVED.value and self._due(record.break_glass_expires_at, now):
            record.status = ApprovalStatus.EXPIRED.value
            record.execution_status = "BLOCKED"
            session.commit()
            session.refresh(record)
            self._audit_event("BREAK_GLASS_EXPIRED", record, "system", "system")
            return True
        return False

    def _time_out(self, session: Session, record: ApprovalRequestRecord) -> None:
        record.status = ApprovalStatus.TIMED_OUT.value
        record.stage = "TERMINAL"
        record.execution_status = "BLOCKED"
        session.commit()
        session.refresh(record)
        self._audit_event("APPROVAL_TIMED_OUT", record, "system", "system")
        self._audit_event("APPROVAL_FINAL_DENY", record, "system", "system", {"reason": "Approval workflow exhausted without authorization."})

    def _break_glass_denial(self, record: ApprovalRequestRecord, workflow: ApprovalWorkflow, approver: ApproverIdentity, reason: str) -> str | None:
        if record.status not in {ApprovalStatus.PENDING_PRIMARY.value, ApprovalStatus.PENDING_FALLBACK.value}:
            return "Approval is not actionable."
        if not workflow.break_glass.enabled:
            return "Break-glass is disabled for this workflow."
        if approver.subject_id == record.agent_id:
            return "Requesting agent cannot grant break-glass access."
        if approver.role not in workflow.break_glass.roles:
            return "Approver role is not authorized for break-glass."
        if workflow.break_glass.require_reason and len(reason) < 20:
            return "Break-glass justification must contain at least 20 characters."
        return None

    def _upgrade_legacy_record(self, session: Session, record: ApprovalRequestRecord) -> None:
        if record.workflow_id and record.status != "PENDING":
            return
        workflow = self._workflows.get(record.workflow_id or "default-high-risk-workflow")
        now = self._now()
        record.workflow_id = record.workflow_id or "default-high-risk-workflow"
        record.status = ApprovalStatus.PENDING_PRIMARY.value if record.status == "PENDING" else record.status
        record.stage = record.stage or "PRIMARY"
        record.primary_expires_at = record.primary_expires_at or record.expires_at or now + timedelta(seconds=workflow.primary.timeout_seconds)
        session.commit()
        session.refresh(record)

    def _workflow(self, record: ApprovalRequestRecord) -> ApprovalWorkflow:
        return self._workflows.get(record.workflow_id or "default-high-risk-workflow")

    def _to_model(self, record: ApprovalRequestRecord, workflow_id: str | None = None, workflow: ApprovalWorkflow | None = None) -> ApprovalRequest:
        resolved_id = workflow_id or record.workflow_id or "default-high-risk-workflow"
        return ApprovalRequest.from_record(record, resolved_id, workflow or self._workflows.get(resolved_id))

    def _audit_event(self, event_type: str, record: ApprovalRequestRecord, actor_id: str, actor_role: str, metadata: dict[str, Any] | None = None) -> None:
        if self._audit is None:
            return
        self._audit.record(
            event_type,
            request_id=record.request_id,
            session_id=record.session_id,
            agent_id=record.agent_id,
            gateway_tool_name=record.gateway_tool_name,
            downstream_server=record.downstream_server,
            downstream_tool_name=record.downstream_tool_name,
            approval_id=record.approval_id,
            approval_status=record.status,
            execution_status=record.execution_status,
            risk_score=record.risk_score,
            risk_level=record.risk_level,
            metadata={"actor": actor_id, "actor_role": actor_role, **(metadata or {})},
        )

    def _blocked_replay(self, record: ApprovalRequestRecord, agent_id: str, reason: str) -> None:
        self._audit_event("APPROVAL_REPLAY_BLOCKED", record, agent_id, "agent", {"reason": reason})

    @staticmethod
    def _stage_event(stage: str, suffix: str) -> str:
        return f"APPROVAL_{'PRIMARY' if stage == 'PRIMARY' else 'FALLBACK'}_{suffix}"

    @staticmethod
    def _normalize_time(value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    def _due(self, value: datetime | None, now: datetime) -> bool:
        return value is not None and self._normalize_time(value) <= now

    def _now(self) -> datetime:
        return self._normalize_time(self._clock.now())

    @staticmethod
    def _require_record(session: Session, approval_id: str) -> ApprovalRequestRecord:
        record = session.scalar(select(ApprovalRequestRecord).where(ApprovalRequestRecord.approval_id == approval_id))
        if record is None:
            raise ApprovalNotFoundError(approval_id)
        return record
