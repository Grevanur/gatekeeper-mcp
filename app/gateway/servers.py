"""Validated downstream MCP server configuration."""

from pathlib import Path

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field

from app.configuration import load_yaml_mapping


class MCPServerDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: AnyHttpUrl
    enabled: bool = True
    trust_tier: str | None = None


class MCPServersConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mcp_servers: dict[str, MCPServerDefinition] = Field(min_length=1)


class DownstreamServerRegistry:
    def __init__(self, configuration: MCPServersConfiguration) -> None:
        self._servers = configuration.mcp_servers

    @classmethod
    def from_config_file(cls, path: Path | str) -> "DownstreamServerRegistry":
        configuration = MCPServersConfiguration.model_validate(load_yaml_mapping(Path(path)))
        return cls(configuration)

    def get(self, server_id: str) -> MCPServerDefinition | None:
        return self._servers.get(server_id)

    def enabled_servers(self) -> dict[str, MCPServerDefinition]:
        return {server_id: server for server_id, server in self._servers.items() if server.enabled}

