"""Exact, fail-closed agent tool permission evaluation."""

from pydantic import BaseModel

from app.auth.identity import AgentsConfiguration


class PermissionResult(BaseModel):
    allowed: bool
    reason: str


class PermissionEvaluator:
    def __init__(self, configuration: AgentsConfiguration) -> None:
        self._agents = configuration.agents

    def evaluate(self, agent_id: str, tool_name: str) -> PermissionResult:
        agent = self._agents.get(agent_id)
        if agent is None:
            return PermissionResult(allowed=False, reason="Agent is not configured.")
        if tool_name in agent.denied_tools:
            return PermissionResult(
                allowed=False,
                reason="Tool is explicitly denied for this agent.",
            )
        if tool_name in agent.allowed_tools or "*" in agent.allowed_tools:
            return PermissionResult(allowed=True, reason="Tool is permitted for this agent.")
        return PermissionResult(allowed=False, reason="Tool is not permitted for this agent.")

