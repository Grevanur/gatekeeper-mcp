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
- SQLite-backed, append-only audit events with recursive argument redaction
- Persistent human approvals with expiry, argument binding, and one-time execution
- Agent-bound session security context that tracks sensitive-data access
- Stateful exfiltration protection: sensitive-data reads followed by external sends are blocked before forwarding

## Architecture

```text
AI agent
   |
   v
Gatekeeper MCP
   |- Identity authentication
   |- Permission evaluation
   |- Session security context
   |- Risk scoring
   |- Policy evaluation
   |- Audit trail
   v
ALLOW | DENY | REQUIRE_APPROVAL
```

The gateway forwards only `ALLOW` decisions to configured downstream MCP servers. `REQUIRE_APPROVAL` creates a persistent request. A different administrative reviewer may approve or deny it, and an approved request is bound to its original arguments and can execute once only.

Audit records contain decision, risk, policy, approval, and execution details. Before persistence, request arguments are recursively redacted for common secret-bearing keys. This is basic logging hygiene, not a full DLP system. For local V1 approval replay, the original arguments are stored only in the local SQLite database; production use requires encryption, secure key management, and stronger identity controls.

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

## Phase 4 demos

With the three demo servers and gateway running as above, run:

```bash
python scripts/run_attack_demo.py
python scripts/run_approval_demo.py
```

The attack demo reads confidential customer data in an agent-bound session, then attempts an external send in that same session. The gateway raises risk to `CRITICAL`, matches `block-sensitive-session-exfiltration`, and prevents downstream execution. The approval demo requests a destructive database action, approves it with the reviewer identity, executes it once, then proves that replay is rejected.

Administrative audit and approval APIs are documented at `/docs`:

```text
GET  /audit/events?agent_id=&session_id=&decision=&risk_level=&tool=&limit=
GET  /audit/events/{event_id}
GET  /approvals
POST /approvals/{approval_id}/approve
POST /approvals/{approval_id}/deny
POST /approvals/{approval_id}/execute
GET  /sessions/{session_id}
```

The supplied development tokens are intentionally local-only: `dev-admin-token`, `dev-reviewer-token`, and `dev-support-token`.
