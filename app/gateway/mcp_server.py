"""Official MCP SDK handlers that adapt Streamable HTTP to the gateway service."""

from collections.abc import Callable
from uuid import uuid4

from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel.server import Server
from mcp.shared.exceptions import MCPError
from mcp_types import CallToolRequestParams, CallToolResult, INVALID_REQUEST, ListToolsResult, PaginatedRequestParams, TextContent
from starlette.responses import PlainTextResponse

from app.auth.identity import AgentIdentity
from app.gateway.errors import GatewayError, GatewayErrorCode
from app.gateway.service import MCPGatewayService


class GatewayMCPMount:
    """Stable FastAPI mount that delegates to a fresh SDK app each lifespan."""

    def __init__(self) -> None:
        self._app: Callable[..., object] | None = None

    def set_app(self, app: Callable[..., object]) -> None:
        self._app = app

    def clear_app(self) -> None:
        self._app = None

    async def __call__(self, scope: object, receive: object, send: object) -> None:
        if self._app is None:
            await PlainTextResponse("MCP gateway is starting.", status_code=503)(scope, receive, send)  # type: ignore[arg-type]
            return
        await self._app(scope, receive, send)  # type: ignore[misc]


def _authenticated_agent(
    context: ServerRequestContext[object], service: MCPGatewayService
) -> AgentIdentity | None:
    request = context.request
    authorization = request.headers.get("authorization") if request is not None else None
    if authorization is None:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return service.authenticate_agent(token)


def _mcp_session_id(context: ServerRequestContext[object]) -> str:
    request = context.request
    if request is not None:
        session_id = request.headers.get("mcp-session-id")
        if session_id and len(session_id) <= 128 and session_id.replace("-", "").replace("_", "").isalnum():
            return session_id
    return str(uuid4())


def _authentication_error(tool_name: str) -> CallToolResult:
    error = GatewayError(
        code=GatewayErrorCode.INVALID_AGENT,
        message="A valid bearer token is required.",
        request_id=str(uuid4()),
        tool_name=tool_name,
    )
    return CallToolResult(content=[TextContent(text=error.model_dump_json())], isError=True)


def create_gateway_mcp_server(service_provider: Callable[[], MCPGatewayService]) -> Server[object]:
    """Create a Streamable-HTTP MCP server backed by the existing gateway service."""

    async def list_tools(
        context: ServerRequestContext[object], _: PaginatedRequestParams | None
    ) -> ListToolsResult:
        service = service_provider()
        agent = _authenticated_agent(context, service)
        if agent is None:
            raise MCPError(INVALID_REQUEST, "Valid bearer token required.")
        return ListToolsResult(tools=await service.list_tools(agent))

    async def call_tool(
        context: ServerRequestContext[object], params: CallToolRequestParams
    ) -> CallToolResult:
        service = service_provider()
        agent = _authenticated_agent(context, service)
        if agent is None:
            return _authentication_error(params.name)
        outcome = await service.call_tool(
            agent,
            params.name,
            params.arguments or {},
            _mcp_session_id(context),
        )
        return outcome.result

    return Server(
        "gatekeeper-mcp",
        version="0.1.0",
        instructions="Security-enforced gateway for downstream MCP tools.",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )
