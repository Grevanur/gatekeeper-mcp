"""The deterministic, fail-closed security orchestration service."""

import logging
from pathlib import Path

from pydantic import BaseModel

from app.auth.identity import IdentityAuthenticator, load_agents_configuration
from app.auth.permissions import PermissionEvaluator, PermissionResult
from app.policy.engine import PolicyEngine
from app.policy.loader import load_policies_configuration
from app.policy.models import PolicyAction, PolicyDecision
from app.risk.engine import RiskEngine
from app.risk.models import RiskAssessment, RiskFactor, RiskLevel
from app.security.models import ToolRequestContext


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False


class SecurityEvaluation(BaseModel):
    request_id: str
    agent_id: str
    tool_name: str
    permission: PermissionResult
    risk: RiskAssessment
    policy: PolicyDecision | None
    final_decision: PolicyAction
    reason: str


class SecurityEvaluator:
    def __init__(
        self,
        identity_authenticator: IdentityAuthenticator,
        permission_evaluator: PermissionEvaluator,
        risk_engine: RiskEngine,
        policy_engine: PolicyEngine,
    ) -> None:
        self.identity_authenticator = identity_authenticator
        self._permission_evaluator = permission_evaluator
        self._risk_engine = risk_engine
        self._policy_engine = policy_engine

    @classmethod
    def from_config_directory(cls, directory: Path | str) -> "SecurityEvaluator":
        config_directory = Path(directory)
        agents = load_agents_configuration(config_directory / "agents.yaml")
        return cls(
            identity_authenticator=IdentityAuthenticator(agents),
            permission_evaluator=PermissionEvaluator(agents),
            risk_engine=RiskEngine.from_config_file(config_directory / "risk.yaml"),
            policy_engine=PolicyEngine(load_policies_configuration(config_directory / "policies.yaml")),
        )

    def evaluate(self, context: ToolRequestContext) -> SecurityEvaluation:
        permission = self._permission_evaluator.evaluate(context.agent.agent_id, context.tool_name)
        try:
            risk = self._risk_engine.assess(context)
        except Exception:
            return self._record(
                context=context,
                permission=permission,
                risk=RiskAssessment(
                    score=100,
                    level=RiskLevel.CRITICAL,
                    factors=[RiskFactor(name="risk_engine_error", value=100)],
                ),
                policy=None,
                final_decision=PolicyAction.DENY,
                reason="Risk evaluation failed; access denied.",
            )

        try:
            policy = self._policy_engine.evaluate(context, risk)
        except Exception:
            return self._record(
                context=context,
                permission=permission,
                risk=risk,
                policy=None,
                final_decision=PolicyAction.DENY,
                reason="Policy evaluation failed; access denied.",
            )

        if not permission.allowed:
            return self._record(
                context=context,
                permission=permission,
                risk=risk,
                policy=policy,
                final_decision=PolicyAction.DENY,
                reason=permission.reason,
            )
        return self._record(
            context=context,
            permission=permission,
            risk=risk,
            policy=policy,
            final_decision=policy.decision,
            reason=policy.reason,
        )

    @staticmethod
    def _record(
        *,
        context: ToolRequestContext,
        permission: PermissionResult,
        risk: RiskAssessment,
        policy: PolicyDecision | None,
        final_decision: PolicyAction,
        reason: str,
    ) -> SecurityEvaluation:
        evaluation = SecurityEvaluation(
            request_id=context.request_id,
            agent_id=context.agent.agent_id,
            tool_name=context.tool_name,
            permission=permission,
            risk=risk,
            policy=policy,
            final_decision=final_decision,
            reason=reason,
        )
        logger.info(
            "SECURITY_DECISION request_id=%s agent=%s tool=%s risk=%s level=%s decision=%s policy=%s",
            evaluation.request_id,
            evaluation.agent_id,
            evaluation.tool_name,
            evaluation.risk.score,
            evaluation.risk.level.value,
            evaluation.final_decision.value,
            evaluation.policy.matched_policy if evaluation.policy else "none",
        )
        return evaluation
