from app.auth.identity import AgentIdentity
from app.policy.models import PolicyAction
from app.security.evaluator import SecurityEvaluator
from app.security.models import ToolRequestContext


def _context(agent: AgentIdentity, tool_name: str, **overrides: object) -> ToolRequestContext:
    return ToolRequestContext.model_validate(
        {
            "request_id": "request-123",
            "session_id": "session-123",
            "agent": agent,
            "tool_name": tool_name,
            **overrides,
        }
    )


def _support_agent() -> AgentIdentity:
    return AgentIdentity(
        agent_id="support-agent",
        owner="demo-user",
        role="support",
        environment="development",
    )


def test_allowed_low_risk_support_search() -> None:
    evaluation = SecurityEvaluator.from_config_directory("config").evaluate(
        _context(_support_agent(), "tickets.search")
    )

    assert evaluation.final_decision is PolicyAction.ALLOW
    assert evaluation.risk.level.value == "LOW"


def test_permission_denial_cannot_be_overridden() -> None:
    evaluation = SecurityEvaluator.from_config_directory("config").evaluate(
        _context(_support_agent(), "secrets.read")
    )

    assert evaluation.final_decision is PolicyAction.DENY
    assert evaluation.permission.allowed is False
    assert evaluation.reason == "Tool is explicitly denied for this agent."


def test_production_delete_requires_approval_for_admin() -> None:
    production_admin = AgentIdentity(
        agent_id="admin-agent",
        owner="demo-user",
        role="admin",
        environment="production",
    )
    evaluation = SecurityEvaluator.from_config_directory("config").evaluate(
        _context(production_admin, "database.delete", is_write_operation=True)
    )

    assert evaluation.permission.allowed is True
    assert evaluation.final_decision is PolicyAction.REQUIRE_APPROVAL
    assert evaluation.policy is not None
    assert evaluation.policy.matched_policy == "production-delete-requires-approval"


def test_sensitive_external_send_is_denied_with_policy_explanation() -> None:
    evaluation = SecurityEvaluator.from_config_directory("config").evaluate(
        _context(
            _support_agent(),
            "external.send",
            is_write_operation=True,
            is_external_destination=True,
            sensitive_data_involved=True,
        )
    )

    assert evaluation.final_decision is PolicyAction.DENY
    assert evaluation.risk.score == 100
    assert evaluation.policy is not None
    assert evaluation.policy.matched_policy == "block-sensitive-external-send"
    assert evaluation.reason == "Tool is not permitted for this agent."
