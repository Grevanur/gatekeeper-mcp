"""Simulated external messaging tool; it never contacts the internet."""

import logging

from mcp.server.mcpserver import MCPServer


logger = logging.getLogger(__name__)
server = MCPServer("messaging", version="0.1.0")


@server.tool(name="external.send", description="Simulate sending data to an external destination.")
def external_send(destination: str, data: str) -> dict[str, str]:
    logger.info("SIMULATED_EXTERNAL_SEND destination=%s", destination)
    return {"status": "SIMULATED", "destination": destination, "message": "No network request was made."}


if __name__ == "__main__":
    server.run(transport="streamable-http", host="127.0.0.1", port=8103)
