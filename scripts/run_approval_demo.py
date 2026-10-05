"""Demonstrate human approval, execution once, and replay prevention."""

import asyncio
import json

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


ENDPOINT = "http://127.0.0.1:8000/mcp/"
SESSION_ID = "approval-demo-session"


async def main() -> None:
    admin_headers = {
        "Authorization": "Bearer dev-admin-token",
        "X-Gateway-Session-Id": SESSION_ID,
    }
    print("=" * 58)
    print("GATEKEEPER MCP — HUMAN APPROVAL DEMO")
    print("=" * 58)
    async with httpx2.AsyncClient(headers=admin_headers) as mcp_http_client:
        async with streamable_http_client(ENDPOINT, http_client=mcp_http_client) as streams:
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as client:
                await client.initialize()
                pending = await client.call_tool(
                    "sensitive-data.database.delete", {"table": "temporary_records"}
                )
    security = json.loads(pending.content[0].text)["security"]
    approval_id = security["approval_id"]
    print("Requested action: database.delete")
    print("Decision:", security["decision"])
    print("Approval ID:", approval_id)

    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer dev-reviewer-token"}
    ) as reviewer_client:
        approved = await reviewer_client.post(
            f"http://127.0.0.1:8000/approvals/{approval_id}/approve"
        )
        print("Human approval status:", approved.json()["status"])

    async with httpx2.AsyncClient(headers=admin_headers) as admin_client:
        executed = await admin_client.post(f"http://127.0.0.1:8000/approvals/{approval_id}/execute")
        replay = await admin_client.post(f"http://127.0.0.1:8000/approvals/{approval_id}/execute")
        print("First execution:", executed.json()["execution_status"])
        print("Replay blocked with:", replay.json()["code"])


if __name__ == "__main__":
    asyncio.run(main())
