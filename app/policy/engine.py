"""First-match policy engine ordered by descending priority."""

from app.policy.models import (
    PoliciesConfiguration,
    PolicyAction,
    PolicyDecision,
    PolicyMatch,
)
from app.risk.models import RiskAssessment, RiskLevel
from app.security.models import ToolRequestContext


class PolicyEngine:
    _risk_order = {
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 1,
        RiskLevel.HIGH: 2,
        RiskLevel.CRITICAL: 3,
    }

    def __init__(self, configuration: PoliciesConfiguration) -> None:
        self._policies = sorted(configuration.policies, key=lambda policy: policy.priority, reverse=True)

    def evaluate(
        self,
        context: ToolRequestContext,
        risk: RiskAssessment,
    ) -> PolicyDecision:
        for policy in self._policies:
            if self._matches(policy.match, context, risk):
                return PolicyDecision(
                    decision=policy.action,
                    matched_policy=policy.name,
                    reason=policy.reason,
                    approval_workflow=policy.approval_workflow,
                )
        return PolicyDecision(
            decision=PolicyAction.DENY,
            matched_policy=None,
            reason="No policy matched; access denied.",
        )

    def _matches(
        self,
        match: PolicyMatch,
        context: ToolRequestContext,
        risk: RiskAssessment,
    ) -> bool:
        if match.tool is not None and match.tool != context.tool_name:
            return False
        if match.agent_id is not None and match.agent_id != context.agent.agent_id:
            return False
        if match.role is not None and match.role != context.agent.role:
            return False
        if match.environment is not None and match.environment != context.agent.environment:
            return False
        if match.risk_level is not None and match.risk_level is not risk.level:
            return False
        if (
            match.minimum_risk_level is not None
            and self._risk_order[risk.level] < self._risk_order[match.minimum_risk_level]
        ):
            return False
        if (
            match.is_external_destination is not None
            and match.is_external_destination != context.is_external_destination
        ):
            return False
        if (
            match.sensitive_data_involved is not None
            and match.sensitive_data_involved != context.sensitive_data_involved
        ):
            return False
        if (
            match.session_sensitive_data_accessed is not None
            and match.session_sensitive_data_accessed != context.session_sensitive_data_accessed
        ):
            return False
        return (
            match.is_write_operation is None
            or match.is_write_operation == context.is_write_operation
        )
