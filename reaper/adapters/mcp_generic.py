"""
Generic MCP server adapter.

Scans MCP server configuration files that are not tied to a
specific agent framework (standalone MCP server deployments).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from reaper.adapters.base import FrameworkAdapter
from reaper.sdk import ProbeTarget, TargetConfig

logger = logging.getLogger("reaper")

# Common MCP config file names across tools
MCP_CONFIG_FILENAMES = (
    "mcp.json",
    "mcp_servers.json",
    ".mcp.json",
    "claude_desktop_config.json",
)


class McpGenericAdapter(FrameworkAdapter):
    """Adapter for standalone / framework-agnostic MCP server configs."""

    framework_id = "mcp_generic"

    def discover_agents(self, search_path: str) -> list[dict]:
        """Find MCP config files under search_path."""
        agents: list[dict] = []
        root = Path(search_path)
        if not root.is_dir():
            return agents

        for name in MCP_CONFIG_FILENAMES:
            for config_file in root.rglob(name):
                agents.append({
                    "name": config_file.stem,
                    "path": str(config_file.parent),
                    "config_file": str(config_file),
                })
        return agents

    def build_target(self, agent: dict) -> TargetConfig:
        config = self.get_config(agent)
        mcp_servers = self.list_mcp_servers(agent)

        return TargetConfig(
            framework=self.framework_id,
            config=config,
            tools=[],
            mcp_servers=mcp_servers,
            system_prompt=None,
            files={Path(agent["config_file"]).name: json.dumps(config, indent=2)}
            if config
            else {},
            metadata={
                "config_file": agent.get("config_file", ""),
                "path": agent["path"],
            },
        )

    def get_config(self, agent: dict) -> dict:
        config_file = agent.get("config_file", "")
        if config_file:
            try:
                return json.loads(Path(config_file).read_text())
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning(f"Failed to read MCP config {config_file}: {exc}")
        return {}

    def discover_probe_targets(
        self, agent: dict, target: TargetConfig
    ) -> list[ProbeTarget]:
        """Build ProbeTargets from MCP server configs."""
        probe_targets: list[ProbeTarget] = []
        for server in target.mcp_servers:
            name = server.get("name", "<unnamed>")
            command = server.get("command", "")
            args = server.get("args", [])
            url = server.get("url", "")

            if command:
                # Stdio transport — command + args
                probe_targets.append(ProbeTarget(
                    endpoint=command,
                    transport="stdio",
                    server_name=name,
                    auth_context=server.get("auth", {}),
                    metadata={
                        "args": args,
                        "env": server.get("env"),
                        "framework": self.framework_id,
                    },
                    config_target=target,
                ))
            elif url:
                # SSE transport — URL endpoint
                probe_targets.append(ProbeTarget(
                    endpoint=url,
                    transport="sse",
                    server_name=name,
                    auth_context=server.get("auth", {}),
                    metadata={"framework": self.framework_id},
                    config_target=target,
                ))

        return probe_targets

    def list_mcp_servers(self, agent: dict) -> list[dict]:
        config = self.get_config(agent)
        servers: list[dict] = []

        # Handle {"mcpServers": {...}} format (Claude Desktop style)
        mcp_servers = config.get("mcpServers", config.get("servers", {}))
        if isinstance(mcp_servers, dict):
            for name, server_config in mcp_servers.items():
                entry = {"name": name}
                if isinstance(server_config, dict):
                    entry.update(server_config)
                servers.append(entry)
        elif isinstance(mcp_servers, list):
            servers = mcp_servers
        return servers
