"""
Stdio MCP transport — spawn MCP server as subprocess, communicate via JSON-RPC.

The server is launched as a child process. Requests are written as JSON-RPC
to stdin; responses are read from stdout. Each message is newline-delimited.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
from itertools import count

from reaper.transport.base import MCPTransport

logger = logging.getLogger("reaper.transport.stdio")

_request_id = count(1)


class StdioTransport(MCPTransport):
    """MCP transport over subprocess stdin/stdout."""

    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.command = command
        self.args = args or []
        self.env = env
        self._process: asyncio.subprocess.Process | None = None

    async def connect(self) -> None:
        """Spawn the MCP server process."""
        # If command is a full shell string, split it
        if not self.args and " " in self.command:
            parts = shlex.split(self.command)
            cmd, args = parts[0], parts[1:]
        else:
            cmd, args = self.command, self.args

        self._process = await asyncio.create_subprocess_exec(
            cmd,
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env,
        )
        logger.debug(f"Spawned MCP server: {cmd} {' '.join(args)} (pid={self._process.pid})")

    async def send_request(self, method: str, params: dict) -> dict:
        """Send a JSON-RPC 2.0 request and read the response."""
        if self._process is None or self._process.stdin is None or self._process.stdout is None:
            raise RuntimeError("Transport not connected")

        request_id = next(_request_id)
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }

        payload = json.dumps(request) + "\n"
        self._process.stdin.write(payload.encode())
        await self._process.stdin.drain()

        # Read one line of response
        line = await self._process.stdout.readline()
        if not line:
            raise ConnectionError("Server closed stdout")

        response = json.loads(line.decode())

        if "error" in response:
            err = response["error"]
            raise ValueError(
                f"JSON-RPC error {err.get('code', '?')}: {err.get('message', '?')}"
            )

        return response.get("result", {})

    async def close(self) -> None:
        """Terminate the server process."""
        if self._process is not None:
            try:
                if self._process.stdin and not self._process.stdin.is_closing():
                    self._process.stdin.close()
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                self._process.kill()
            finally:
                self._process = None
