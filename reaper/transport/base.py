"""
Abstract MCP transport interface.

All transports implement JSON-RPC 2.0 over their respective channels.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class MCPTransport(ABC):
    """Base class for MCP server communication."""

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the MCP server."""

    @abstractmethod
    async def send_request(self, method: str, params: dict) -> dict:
        """Send a JSON-RPC request and return the result.

        Raises on transport errors. Returns the 'result' field from
        a successful JSON-RPC response, or raises ValueError on
        JSON-RPC error responses.
        """

    @abstractmethod
    async def close(self) -> None:
        """Close the connection and release resources."""

    async def initialize(self) -> dict:
        """Send MCP initialize handshake."""
        return await self.send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "reaper-scanner", "version": "0.2.0"},
            },
        )

    async def list_tools(self) -> dict:
        """Call tools/list on the MCP server."""
        return await self.send_request("tools/list", {})

    async def call_tool(self, name: str, arguments: dict) -> dict:
        """Call tools/call on the MCP server."""
        return await self.send_request(
            "tools/call", {"name": name, "arguments": arguments}
        )
