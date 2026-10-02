"""Low-risk tools served over local Streamable HTTP."""

from mcp.server.mcpserver import MCPServer


server = MCPServer("normal-tools", version="0.1.0")


@server.tool(name="tickets.search", description="Search demo support tickets.")
def tickets_search(query: str) -> dict[str, object]:
    return {
        "query": query,
        "tickets": [
            {"id": "TICK-101", "subject": "Login issue", "status": "open"},
            {"id": "TICK-102", "subject": "Password reset", "status": "resolved"},
        ],
    }


@server.tool(name="knowledge.search", description="Search demo internal knowledge.")
def knowledge_search(query: str) -> dict[str, object]:
    return {"query": query, "results": [{"title": "Account access guide", "classification": "INTERNAL"}]}


if __name__ == "__main__":
    server.run(transport="streamable-http", host="127.0.0.1", port=8101)
