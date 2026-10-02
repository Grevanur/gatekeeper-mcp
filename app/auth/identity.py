"""Development bearer-token authentication for known agents."""

from pathlib import Path

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.configuration import load_yaml_mapping


class AgentIdentity(BaseModel):
    agent_id: str
    owner: str
    role: str
    environment: str


class ConfiguredAgent(AgentIdentity):
    model_config = ConfigDict(extra="forbid")

    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)


class AgentsConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tokens: dict[str, str]
    agents: dict[str, ConfiguredAgent]

    @model_validator(mode="after")
    def validate_token_agents(self) -> "AgentsConfiguration":
        unknown_agents = set(self.tokens.values()) - set(self.agents)
        if unknown_agents:
            raise ValueError(f"Tokens reference unknown agents: {sorted(unknown_agents)}")
        mismatched_ids = [
            name for name, agent in self.agents.items() if agent.agent_id != name
        ]
        if mismatched_ids:
            raise ValueError(f"Agent keys must match agent_id: {mismatched_ids}")
        return self


def load_agents_configuration(path: Path | str) -> AgentsConfiguration:
    """Load token-to-agent mappings and agent permissions from YAML."""

    return AgentsConfiguration.model_validate(load_yaml_mapping(Path(path)))


class IdentityAuthenticator:
    """Resolve exact development bearer tokens to configured identities."""

    def __init__(self, configuration: AgentsConfiguration) -> None:
        self._configuration = configuration

    def authenticate(self, token: str) -> AgentIdentity | None:
        agent_id = self._configuration.tokens.get(token)
        if agent_id is None:
            return None
        return AgentIdentity.model_validate(self._configuration.agents[agent_id])


bearer_scheme = HTTPBearer(auto_error=False)


def get_current_agent(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AgentIdentity:
    """FastAPI dependency that rejects absent or invalid development tokens."""

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")

    identity = request.app.state.identity_authenticator.authenticate(credentials.credentials)
    if identity is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token")
    return identity
