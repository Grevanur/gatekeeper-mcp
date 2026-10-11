"""Canonical, security-relevant bindings for one approved operation."""

import hashlib
import json
from typing import Any

from pydantic import BaseModel, Field


def canonical_json(value: Any) -> str:
    """Encode JSON-compatible values with recursive mapping-key ordering."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def hash_canonical(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def normalize_destination(value: Any, destination_type: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if destination_type in {"email", "database"}:
        normalized = normalized.lower()
    return normalized


class ApprovalBinding(BaseModel):
    agent_id: str
    session_id: str
    gateway_tool_name: str
    downstream_server: str
    downstream_tool_name: str
    canonical_arguments_hash: str
    destination_type: str | None = None
    destination_fingerprint: str | None = None
    environment: str
    security_context_hash: str
    policy_id: str | None = None
    policy_version: int | None = None
    security_context: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        agent_id: str,
        session_id: str,
        gateway_tool_name: str,
        downstream_server: str,
        downstream_tool_name: str,
        arguments: dict[str, Any],
        destination: Any = None,
        destination_type: str | None = None,
        environment: str,
        security_context: dict[str, Any],
        policy_id: str | None,
        policy_version: int | None,
    ) -> "ApprovalBinding":
        normalized_destination = normalize_destination(destination, destination_type)
        return cls(
            agent_id=agent_id,
            session_id=session_id,
            gateway_tool_name=gateway_tool_name,
            downstream_server=downstream_server,
            downstream_tool_name=downstream_tool_name,
            canonical_arguments_hash=hash_canonical(arguments),
            destination_type=destination_type,
            destination_fingerprint=hash_canonical(normalized_destination) if normalized_destination else None,
            environment=environment,
            security_context_hash=hash_canonical(security_context),
            policy_id=policy_id,
            policy_version=policy_version,
            security_context=security_context,
        )


def binding_diff(expected: ApprovalBinding, actual: ApprovalBinding) -> list[str]:
    fields = (
        "agent_id",
        "session_id",
        "gateway_tool_name",
        "downstream_server",
        "downstream_tool_name",
        "canonical_arguments_hash",
        "destination_type",
        "destination_fingerprint",
        "environment",
        "security_context_hash",
    )
    labels = {
        "canonical_arguments_hash": "arguments",
        "destination_fingerprint": "destination",
        "security_context_hash": "security_context",
    }
    return [labels.get(field, field) for field in fields if getattr(expected, field) != getattr(actual, field)]
