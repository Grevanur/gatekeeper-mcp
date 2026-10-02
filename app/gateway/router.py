"""Namespaced gateway tool-name construction and parsing."""

from dataclasses import dataclass
import re


_SERVER_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_TOOL_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]+(?:[.-][a-zA-Z0-9_]+)*$")


class InvalidGatewayToolName(ValueError):
    """Raised when a client supplies an unsafe or malformed tool name."""


@dataclass(frozen=True)
class GatewayToolRoute:
    server_id: str
    downstream_tool_name: str


def build_gateway_tool_name(server_id: str, downstream_tool_name: str) -> str:
    """Expose one downstream tool with a collision-safe server namespace."""

    if not _SERVER_ID_PATTERN.fullmatch(server_id):
        raise InvalidGatewayToolName("Server ID is malformed.")
    if not _TOOL_NAME_PATTERN.fullmatch(downstream_tool_name):
        raise InvalidGatewayToolName("Downstream tool name is malformed.")
    return f"{server_id}.{downstream_tool_name}"


def parse_gateway_tool_name(gateway_tool_name: str) -> GatewayToolRoute:
    """Resolve a namespaced tool name without scattering string parsing."""

    if gateway_tool_name.count(".") < 1:
        raise InvalidGatewayToolName("Gateway tool names must include a server namespace.")
    server_id, downstream_tool_name = gateway_tool_name.split(".", maxsplit=1)
    build_gateway_tool_name(server_id, downstream_tool_name)
    return GatewayToolRoute(server_id=server_id, downstream_tool_name=downstream_tool_name)

