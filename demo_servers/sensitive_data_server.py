"""Fake sensitive-data tools for security demonstrations only."""

import logging

from mcp.server.mcpserver import MCPServer


logger = logging.getLogger(__name__)
server = MCPServer("sensitive-data", version="0.1.0")


@server.tool(name="customer.read", description="Read a fake confidential customer record.")
def customer_read(customer_id: str) -> dict[str, str]:
    return {
        "customer_id": customer_id,
        "name": "Alice Demo",
        "email": "alice@example.local",
        "account_tier": "enterprise",
        "classification": "CONFIDENTIAL",
    }


@server.tool(name="secrets.read", description="Read a fake secret for denial demonstrations.")
def secrets_read() -> dict[str, str]:
    logger.info("SIMULATED_SECRET_READ")
    return {"secret": "DEMO_ONLY_NOT_A_REAL_SECRET", "classification": "SECRET"}


@server.tool(name="database.delete", description="Simulate a destructive database action.")
def database_delete(table: str) -> dict[str, str]:
    logger.info("SIMULATED_DATABASE_DELETE table=%s", table)
    return {"status": "SIMULATED_ONLY", "table": table, "message": "No data was deleted."}


if __name__ == "__main__":
    server.run(transport="streamable-http", host="127.0.0.1", port=8102)
