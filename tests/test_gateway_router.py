import pytest

from app.gateway.router import (
    InvalidGatewayToolName,
    build_gateway_tool_name,
    parse_gateway_tool_name,
)


def test_gateway_tool_names_round_trip_without_collisions() -> None:
    tool_name = build_gateway_tool_name("normal-tools", "tickets.search")

    assert tool_name == "normal-tools.tickets.search"
    assert parse_gateway_tool_name(tool_name).server_id == "normal-tools"
    assert parse_gateway_tool_name(tool_name).downstream_tool_name == "tickets.search"


@pytest.mark.parametrize("tool_name", ["tickets", ".tickets.search", "normal-tools.", "bad/id.tool"])
def test_malformed_gateway_tool_names_are_rejected(tool_name: str) -> None:
    with pytest.raises(InvalidGatewayToolName):
        parse_gateway_tool_name(tool_name)
