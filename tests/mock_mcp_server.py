"""
Mock MCP Server — Configurable test server for Wedge 2 probe testing.

Communicates via stdio (stdin/stdout) using JSON-RPC 2.0.
Configurable auth, tools, validation, and delay.

Usage:
    python -m tests.mock_mcp_server                          # No auth
    python -m tests.mock_mcp_server --require-auth            # Require auth
    python -m tests.mock_mcp_server --valid-tokens tok1,tok2  # Specific tokens
"""

from __future__ import annotations

import argparse
import json
import sys
import time


class MockMCPServer:
    """A configurable mock MCP server for testing."""

    def __init__(
        self,
        require_auth: bool = False,
        valid_tokens: list[str] | None = None,
        tools: list[dict] | None = None,
        validate_params: bool = False,
        delay_ms: int = 0,
    ) -> None:
        self.require_auth = require_auth
        self.valid_tokens = valid_tokens or []
        self.tools = tools or [
            {
                "name": "echo",
                "description": "Echo the input back",
                "inputSchema": {
                    "type": "object",
                    "properties": {"message": {"type": "string"}},
                    "required": ["message"],
                },
            },
            {
                "name": "read_file",
                "description": "Read a file from disk",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        ]
        self.validate_params = validate_params
        self.delay_ms = delay_ms
        self._authenticated = False

    def handle_request(self, request: dict) -> dict:
        """Process a JSON-RPC request and return a response."""
        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", {})

        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)

        # Auth check — initialize carries auth context
        if method == "initialize":
            return self._handle_initialize(req_id, params)

        # For all other methods, check auth if required
        if self.require_auth and not self._authenticated:
            return self._error(req_id, -32001, "Authentication required")

        if method == "tools/list":
            return self._handle_list_tools(req_id)
        if method == "tools/call":
            return self._handle_call_tool(req_id, params)
        if method == "notifications/initialized":
            # Client notification, no response needed but we'll ack
            return self._result(req_id, {})

        return self._error(req_id, -32601, f"Method not found: {method}")

    def _handle_initialize(self, req_id: int | str, params: dict) -> dict:
        """Handle the MCP initialize handshake."""
        # Check auth from client info metadata
        client_info = params.get("clientInfo", {})
        auth_token = client_info.get("auth_token", "")

        if self.require_auth:
            if not auth_token:
                return self._error(req_id, -32001, "Authentication required")
            if self.valid_tokens and auth_token not in self.valid_tokens:
                return self._error(req_id, -32002, "Invalid authentication token")

        self._authenticated = True
        return self._result(
            req_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-mcp-server", "version": "0.1.0"},
            },
        )

    def _handle_list_tools(self, req_id: int | str) -> dict:
        """Return the configured tool list."""
        return self._result(req_id, {"tools": self.tools})

    def _handle_call_tool(self, req_id: int | str, params: dict) -> dict:
        """Handle a tool invocation."""
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        # Find the tool
        tool = next((t for t in self.tools if t["name"] == tool_name), None)
        if tool is None:
            return self._error(req_id, -32602, f"Unknown tool: {tool_name}")

        # Optional parameter validation
        if self.validate_params:
            schema = tool.get("inputSchema", {})
            required = schema.get("required", [])
            for field in required:
                if field not in arguments:
                    return self._error(
                        req_id, -32602, f"Missing required parameter: {field}"
                    )

        # Return a mock result
        return self._result(
            req_id,
            {
                "content": [
                    {
                        "type": "text",
                        "text": f"Mock result for {tool_name}({json.dumps(arguments)})",
                    }
                ]
            },
        )

    @staticmethod
    def _result(req_id: int | str | None, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    @staticmethod
    def _error(req_id: int | str | None, code: int, message: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }


def run_stdio(server: MockMCPServer) -> None:
    """Run the mock server over stdin/stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            response = server._error(None, -32700, "Parse error")
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            continue

        response = server.handle_request(request)
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock MCP Server for testing")
    parser.add_argument("--require-auth", action="store_true", help="Require authentication")
    parser.add_argument("--valid-tokens", type=str, default="", help="Comma-separated valid tokens")
    parser.add_argument("--validate-params", action="store_true", help="Validate tool parameters")
    parser.add_argument("--delay-ms", type=int, default=0, help="Response delay in ms")
    args = parser.parse_args()

    valid_tokens = [t.strip() for t in args.valid_tokens.split(",") if t.strip()]

    server = MockMCPServer(
        require_auth=args.require_auth,
        valid_tokens=valid_tokens,
        validate_params=args.validate_params,
        delay_ms=args.delay_ms,
    )
    run_stdio(server)


if __name__ == "__main__":
    main()
