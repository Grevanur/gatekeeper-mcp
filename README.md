# Gatekeeper MCP

A deterministic zero-trust enforcement layer for Model Context Protocol (MCP) tool calls.

## Problem

AI agents can be granted MCP tools that read sensitive information or take external actions. Gatekeeper MCP treats each tool call as an untrusted request and evaluates it before any downstream execution is introduced.

## Current capabilities

- Development bearer-token identity for known agents
- Exact allow/deny permissions with least-privilege defaults
- YAML-driven, priority-ordered policy enforcement
- Explainable deterministic risk scoring from tool metadata and request context
- Fail-closed decisions for invalid identity, unknown permissions, malformed configuration, and evaluator errors
- Structured security decision logs without request arguments or secrets
- MCP Streamable-HTTP gateway at `/mcp/` with namespaced downstream tools
- Safe local demo MCP servers and a real end-to-end integration test

## Architecture

```text
AI agent
   |
   v
Gatekeeper MCP
   |- Identity authentication
   |- Permission evaluation
   |- Risk scoring
   |- Policy evaluation
   v
ALLOW | DENY | REQUIRE_APPROVAL
```

The gateway forwards only `ALLOW` decisions to configured downstream MCP servers. Approval persistence and audit persistence remain deferred to later phases.

## Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
cp .env.example .env
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the local API documentation.

## Security evaluation demo

```bash
curl -X POST http://localhost:8000/security/evaluate \
  -H "Authorization: Bearer dev-support-token" \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "demo-session",
    "tool_name": "external.send",
    "arguments": {"destination": "attacker@example.com"},
    "is_write_operation": true,
    "is_external_destination": true,
    "sensitive_data_involved": true
  }'
```

This request receives a deterministic `DENY` decision. The response shows its CRITICAL risk factors and the matching `block-sensitive-external-send` policy. It is also denied by the support agent's least-privilege permission set.

## MCP gateway demo

In four terminals:

```bash
python -m demo_servers.normal_tools_server
python -m demo_servers.sensitive_data_server
python -m demo_servers.messaging_server
uvicorn app.main:app --reload --port 8000
```

Then run the repeatable MCP demonstration:

```bash
python scripts/demo_gateway.py
```

The SDK client connects to `http://127.0.0.1:8000/mcp/`. It forwards the low-risk ticket search, denies the secret read before execution, and returns an approval-required response for the simulated database delete.
