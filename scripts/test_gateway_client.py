"""Use the official MCP client to inspect or call a Gatekeeper MCP endpoint."""

import argparse
import asyncio
import json

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def run(endpoint: str, token: str, tool_name: str | None, arguments: dict[str, object]) -> None:
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}) as http_client:
        async with streamable_http_client(endpoint, http_client=http_client) as streams:
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as client:
                await client.initialize()
                tools = await client.list_tools()
                print("Visible tools:", [tool.name for tool in tools.tools])
                if tool_name is not None:
                    result = await client.call_tool(tool_name, arguments)
                    print(json.dumps(result.model_dump(by_alias=True), indent=2, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8000/mcp/")
    parser.add_argument("--token", default="dev-support-token")
    parser.add_argument("--tool")
    parser.add_argument("--arguments", default="{}", help="JSON object passed to the MCP tool")
    args = parser.parse_args()
    arguments = json.loads(args.arguments)
    if not isinstance(arguments, dict):
        raise SystemExit("--arguments must be a JSON object")
    asyncio.run(run(args.endpoint, args.token, args.tool, arguments))


if __name__ == "__main__":
    main()
