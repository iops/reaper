"""
Transport factory — create the appropriate transport for a ProbeTarget.
"""

from __future__ import annotations

from reaper.sdk import ProbeTarget
from reaper.transport.base import MCPTransport
from reaper.transport.stdio import StdioTransport


def create_transport(target: ProbeTarget) -> MCPTransport:
    """Create the appropriate MCP transport for a probe target."""
    if target.transport == "stdio":
        args = target.metadata.get("args", [])
        env = target.metadata.get("env")
        return StdioTransport(command=target.endpoint, args=args, env=env)

    if target.transport == "sse":
        raise NotImplementedError("SSE transport not yet implemented")

    if target.transport == "websocket":
        raise NotImplementedError("WebSocket transport not yet implemented")

    raise ValueError(f"Unknown transport type: {target.transport}")
