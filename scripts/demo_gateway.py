"""Run one allowed, one denied, and one approval-required MCP gateway scenario."""

import asyncio
import json

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


ENDPOINT = "http://127.0.0.1:8000/mcp/"


def _security_response(result: object) -> dict[str, object] | None:
    content = getattr(result, "content", [])
    if not content:
        return None
    try:
        return json.loads(content[0].text).get("security")
    except (AttributeError, json.JSONDecodeError):
        return None


async def _call(token: str, tool_name: str, arguments: dict[str, object]) -> object:
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}) as http_client:
        async with streamable_http_client(ENDPOINT, http_client=http_client) as streams:
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as client:
                await client.initialize()
                return await client.call_tool(tool_name, arguments)


async def main() -> None:
    scenarios = [
        ("Demo 1", "dev-support-token", "normal-tools.tickets.search", {"query": "login"}),
        ("Demo 2", "dev-support-token", "sensitive-data.secrets.read", {}),
        ("Demo 3", "dev-admin-token", "sensitive-data.database.delete", {"table": "customers"}),
    ]
    for label, token, tool_name, arguments in scenarios:
        result = await _call(token, tool_name, arguments)
        security = _security_response(result)
        print(f"\n{label}\nTool: {tool_name}")
        if security:
            print("SECURITY:", security["decision"])
            print("Reason:", security["message"])
            print("Downstream execution: NOT PERFORMED")
        else:
            print("SECURITY: ALLOW")
            print("Result:", result.content[0].text)


if __name__ == "__main__":
    asyncio.run(main())
