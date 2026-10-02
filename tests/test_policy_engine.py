import pytest
from pydantic import ValidationError

from app.auth.identity import AgentIdentity
from app.policy.engine import PolicyEngine
from app.policy.loader import load_policies_configuration
from app.policy.models import PoliciesConfiguration, PolicyAction
from app.risk.models import RiskAssessment, RiskLevel
from app.security.models import ToolRequestContext


def _context(**overrides: object) -> ToolRequestContext:
    agent = AgentIdentity(
        agent_id="support-agent",
        owner="demo-user",
        role="support",
        environment="development",
    )
    return ToolRequestContext.model_validate(
        {
            "request_id": "request-1",
            "session_id": "session-1",
            "agent": agent,
            "tool_name": "tickets.search",
            **overrides,
        }
    )


def _risk(level: RiskLevel = RiskLevel.LOW) -> RiskAssessment:
    score = {RiskLevel.LOW: 5, RiskLevel.MEDIUM: 40, RiskLevel.HIGH: 70, RiskLevel.CRITICAL: 90}[level]
    return RiskAssessment(score=score, level=level, factors=[])


def test_exact_tool_and_multiple_conditions_match_highest_priority_policy() -> None:
    decision = PolicyEngine(load_policies_configuration("config/policies.yaml")).evaluate(
        _context(
            tool_name="external.send",
            is_external_destination=True,
            sensitive_data_involved=True,
        ),
        _risk(RiskLevel.CRITICAL),
    )

    assert decision.decision is PolicyAction.DENY
    assert decision.matched_policy == "block-sensitive-external-send"


def test_environment_rule_precedes_generic_high_risk_rule() -> None:
    production_admin = AgentIdentity(
        agent_id="admin-agent", owner="demo-user", role="admin", environment="production"
    )
    decision = PolicyEngine(load_policies_configuration("config/policies.yaml")).evaluate(
        _context(tool_name="database.delete", agent=production_admin), _risk(RiskLevel.CRITICAL)
    )

    assert decision.decision is PolicyAction.REQUIRE_APPROVAL
    assert decision.matched_policy == "production-delete-requires-approval"


def test_role_match_and_risk_level_match_are_supported() -> None:
    configuration = PoliciesConfiguration.model_validate(
        {
            "policies": [
                {
                    "name": "support-medium",
                    "priority": 10,
                    "match": {"role": "support", "risk_level": "MEDIUM"},
                    "action": "DENY",
                    "reason": "Test role and level match.",
                },
                {
                    "name": "fallback",
                    "priority": 1,
                    "match": {},
                    "action": "ALLOW",
                    "reason": "Fallback.",
                },
            ]
        }
    )

    decision = PolicyEngine(configuration).evaluate(_context(), _risk(RiskLevel.MEDIUM))
    assert decision.matched_policy == "support-medium"


def test_default_rule_allows_low_risk_call() -> None:
    decision = PolicyEngine(load_policies_configuration("config/policies.yaml")).evaluate(
        _context(), _risk()
    )

    assert decision.decision is PolicyAction.ALLOW
    assert decision.matched_policy == "default-allow"


def test_malformed_policy_is_rejected() -> None:
    with pytest.raises(ValidationError):
        PoliciesConfiguration.model_validate(
            {
                "policies": [
                    {
                        "name": "bad-policy",
                        "priority": 1,
                        "match": {"unexpected_matcher": True},
                        "action": "ALLOW",
                        "reason": "Invalid.",
                    }
                ]
            }
        )
