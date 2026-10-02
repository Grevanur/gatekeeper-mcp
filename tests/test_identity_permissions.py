from app.auth.identity import IdentityAuthenticator, load_agents_configuration
from app.auth.permissions import PermissionEvaluator


def _configuration():
    return load_agents_configuration("config/agents.yaml")


def test_valid_development_token_resolves_agent_identity() -> None:
    identity = IdentityAuthenticator(_configuration()).authenticate("dev-support-token")

    assert identity is not None
    assert identity.agent_id == "support-agent"
    assert identity.role == "support"


def test_invalid_token_is_not_authenticated() -> None:
    assert IdentityAuthenticator(_configuration()).authenticate("not-a-token") is None


def test_exact_allow_and_exact_deny_are_enforced() -> None:
    evaluator = PermissionEvaluator(_configuration())

    assert evaluator.evaluate("support-agent", "tickets.search").allowed is True
    denied = evaluator.evaluate("support-agent", "secrets.read")
    assert denied.allowed is False
    assert denied.reason == "Tool is explicitly denied for this agent."


def test_wildcard_allow_does_not_override_explicit_deny() -> None:
    configuration = _configuration()
    configuration.agents["admin-agent"].denied_tools.append("shell.execute")
    evaluator = PermissionEvaluator(configuration)

    assert evaluator.evaluate("admin-agent", "customer.read").allowed is True
    assert evaluator.evaluate("admin-agent", "shell.execute").allowed is False


def test_unknown_agent_and_unknown_tool_are_denied() -> None:
    evaluator = PermissionEvaluator(_configuration())

    assert evaluator.evaluate("unknown-agent", "tickets.search").allowed is False
    assert evaluator.evaluate("support-agent", "unknown.tool").allowed is False
