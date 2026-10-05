"""Approval persistence with expiry, request binding, and one-time claims."""

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalRequest, ApprovalStatus, ExecutionClaim
from app.audit.redaction import sanitize_arguments
from app.database.models import ApprovalRequestRecord


class ApprovalNotFoundError(LookupError):
    pass


class ApprovalDeniedError(PermissionError):
    pass


class ApprovalExpiredError(PermissionError):
    pass


class ApprovalAlreadyConsumedError(PermissionError):
    pass


class ApprovalArgumentMismatchError(PermissionError):
    pass


def hash_arguments(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


class ApprovalService:
    def __init__(self, session_factory: Callable[[], Session], ttl_seconds: int) -> None:
        self._session_factory = session_factory
        self._ttl_seconds = ttl_seconds

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
        reason: str,
    ) -> ApprovalRequest:
        now = datetime.now(timezone.utc)
        record = ApprovalRequestRecord(
            approval_id=f"apr_{uuid4().hex}",
            created_at=now,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
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
        )
        with self._session_factory() as session:
            session.add(record)
            session.commit()
            session.refresh(record)
            return ApprovalRequest.from_record(record)

    def get(self, approval_id: str) -> ApprovalRequest:
        with self._session_factory() as session:
            record = self._require_record(session, approval_id)
            self._expire_if_needed(session, record)
            return ApprovalRequest.from_record(record)

    def list(self) -> list[ApprovalRequest]:
        with self._session_factory() as session:
            records = session.scalars(
                select(ApprovalRequestRecord).order_by(ApprovalRequestRecord.created_at.desc())
            ).all()
            for record in records:
                self._expire_if_needed(session, record)
            return [ApprovalRequest.from_record(record) for record in records]

    def approve(self, approval_id: str, approver_id: str) -> ApprovalRequest:
        with self._session_factory() as session:
            record = self._require_record(session, approval_id)
            self._expire_if_needed(session, record)
            if record.agent_id == approver_id:
                raise ApprovalDeniedError("Requesting agent cannot approve its own action.")
            if record.status != ApprovalStatus.PENDING.value:
                raise ApprovalDeniedError("Approval is not pending.")
            record.status = ApprovalStatus.APPROVED.value
            record.approved_by = approver_id
            record.approved_at = datetime.now(timezone.utc)
            session.commit()
            session.refresh(record)
            return ApprovalRequest.from_record(record)

    def deny(self, approval_id: str, approver_id: str) -> ApprovalRequest:
        with self._session_factory() as session:
            record = self._require_record(session, approval_id)
            self._expire_if_needed(session, record)
            if record.status != ApprovalStatus.PENDING.value:
                raise ApprovalDeniedError("Approval is not pending.")
            record.status = ApprovalStatus.DENIED.value
            record.denied_by = approver_id
            record.denied_at = datetime.now(timezone.utc)
            session.commit()
            session.refresh(record)
            return ApprovalRequest.from_record(record)

    def claim_execution(
        self, approval_id: str, agent_id: str, arguments: dict[str, Any] | None = None
    ) -> ExecutionClaim:
        with self._session_factory() as session:
            record = self._require_record(session, approval_id)
            self._expire_if_needed(session, record)
            if record.agent_id != agent_id:
                raise ApprovalDeniedError("Approval is bound to a different agent.")
            if record.status == ApprovalStatus.EXPIRED.value:
                raise ApprovalExpiredError("Approval has expired.")
            if record.status != ApprovalStatus.APPROVED.value:
                raise ApprovalAlreadyConsumedError("Approval is not available for execution.")
            if arguments is not None and hash_arguments(arguments) != record.argument_hash:
                raise ApprovalArgumentMismatchError("Arguments do not match the approved request.")
            claimed = session.execute(
                update(ApprovalRequestRecord)
                .where(
                    ApprovalRequestRecord.id == record.id,
                    ApprovalRequestRecord.status == ApprovalStatus.APPROVED.value,
                )
                .values(status=ApprovalStatus.EXECUTING.value, execution_status="EXECUTING")
            )
            if claimed.rowcount != 1:
                raise ApprovalAlreadyConsumedError("Approval was already claimed for execution.")
            session.commit()
            session.refresh(record)
            return ExecutionClaim(
                approval=ApprovalRequest.from_record(record), original_arguments=record.original_arguments
            )

    def complete_execution(self, approval_id: str, success: bool) -> ApprovalRequest:
        with self._session_factory() as session:
            record = self._require_record(session, approval_id)
            if record.status != ApprovalStatus.EXECUTING.value:
                raise ApprovalAlreadyConsumedError("Approval was not claimed for execution.")
            record.status = ApprovalStatus.EXECUTED.value if success else ApprovalStatus.FAILED.value
            record.execution_status = "EXECUTED" if success else "DOWNSTREAM_FAILED"
            record.executed_at = datetime.now(timezone.utc)
            session.commit()
            session.refresh(record)
            return ApprovalRequest.from_record(record)

    @staticmethod
    def _normalize_time(value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    def _expire_if_needed(self, session: Session, record: ApprovalRequestRecord) -> bool:
        if record.status == ApprovalStatus.PENDING.value and self._normalize_time(record.expires_at) <= datetime.now(timezone.utc):
            record.status = ApprovalStatus.EXPIRED.value
            record.execution_status = "BLOCKED"
            session.commit()
            session.refresh(record)
            return True
        return False

    @staticmethod
    def _require_record(session: Session, approval_id: str) -> ApprovalRequestRecord:
        record = session.scalar(
            select(ApprovalRequestRecord).where(ApprovalRequestRecord.approval_id == approval_id)
        )
        if record is None:
            raise ApprovalNotFoundError(approval_id)
        return record
