from app.gateway.metadata import ToolMetadataRegistry
from app.gateway.servers import DownstreamServerRegistry


def test_server_registry_exposes_only_enabled_servers() -> None:
    registry = DownstreamServerRegistry.from_config_file("config/mcp_servers.yaml")

    assert set(registry.enabled_servers()) == {"normal-tools", "sensitive-data", "messaging"}
    assert str(registry.get("normal-tools").url) == "http://127.0.0.1:8101/mcp"


def test_tool_metadata_requires_a_fully_qualified_gateway_tool() -> None:
    registry = ToolMetadataRegistry.from_config_file("config/tool_metadata.yaml")

    metadata = registry.get("messaging.external.send")
    assert metadata is not None
    assert metadata.external_destination is True
    assert registry.get("external.send") is None
