from app.auth.identity import AgentIdentity
from app.risk.engine import RiskEngine
from app.risk.models import RiskLevel
from app.security.models import ToolRequestContext


def _context(tool_name: str, **overrides: object) -> ToolRequestContext:
    agent = AgentIdentity(
        agent_id="support-agent",
        owner="demo-user",
        role="support",
        environment="development",
    )
    values = {
        "request_id": "request-1",
        "session_id": "session-1",
        "agent": agent,
        "tool_name": tool_name,
        **overrides,
    }
    return ToolRequestContext.model_validate(values)


def test_normal_read_is_low_risk() -> None:
    assessment = RiskEngine.from_config_file("config/risk.yaml").assess(_context("tickets.search"))

    assert assessment.score == 5
    assert assessment.level is RiskLevel.LOW


def test_unknown_tool_includes_default_and_modifier() -> None:
    assessment = RiskEngine.from_config_file("config/risk.yaml").assess(_context("unknown.tool"))

    assert assessment.score == 80
    assert assessment.level is RiskLevel.HIGH
    assert [factor.name for factor in assessment.factors] == ["base_tool_risk", "unknown_tool"]


def test_contextual_modifiers_are_explainable() -> None:
    production_agent = AgentIdentity(
        agent_id="admin-agent",
        owner="demo-user",
        role="admin",
        environment="production",
    )
    assessment = RiskEngine.from_config_file("config/risk.yaml").assess(
        _context(
            "database.update",
            agent=production_agent,
            is_write_operation=True,
            is_external_destination=True,
            sensitive_data_involved=True,
        )
    )

    assert assessment.score == 100
    assert assessment.level is RiskLevel.CRITICAL
    assert {factor.name for factor in assessment.factors} == {
        "base_tool_risk",
        "external_destination",
        "sensitive_data",
        "production_environment",
        "write_operation",
    }


def test_high_baseline_is_clamped_to_100() -> None:
    assessment = RiskEngine.from_config_file("config/risk.yaml").assess(
        _context(
            "database.delete",
            is_write_operation=True,
            is_external_destination=True,
            sensitive_data_involved=True,
        )
    )

    assert assessment.score == 100
    assert assessment.level is RiskLevel.CRITICAL


def test_sensitive_session_increases_external_risk_with_explicit_factors() -> None:
    assessment = RiskEngine.from_config_file("config/risk.yaml").assess(
        _context(
            "external.send",
            is_write_operation=True,
            is_external_destination=True,
            session_sensitive_data_accessed=True,
        )
    )

    assert assessment.score == 100
    assert {factor.name for factor in assessment.factors} >= {
        "recent_sensitive_access",
        "sensitive_to_external_transition",
    }
