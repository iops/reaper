"""
OpenClaw framework adapter.

Discovers OpenClaw Gateway agent workspaces and extracts their
configuration into TargetConfig objects for the scanner engine.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from reaper.adapters.base import FrameworkAdapter
from reaper.sdk import TargetConfig

logger = logging.getLogger("reaper")


class OpenClawAdapter(FrameworkAdapter):
    """Adapter for OpenClaw Gateway agents."""

    framework_id = "openclaw"

    def discover_agents(self, search_path: str) -> list[dict]:
        """Find OpenClaw agent workspaces by locating AGENTS.md files."""
        agents: list[dict] = []
        root = Path(search_path)
        if not root.is_dir():
            return agents

        for agents_md in root.rglob("AGENTS.md"):
            workspace = agents_md.parent
            agents.append({
                "name": workspace.name,
                "path": str(workspace),
            })
        return agents

    def build_target(self, agent: dict) -> TargetConfig:
        workspace = Path(agent["path"])
        config = self.get_config(agent)
        tools = self.list_tools(agent)
        mcp_servers = self.list_mcp_servers(agent)
        system_prompt = self.get_system_prompt(agent)
        files = self._read_workspace_files(workspace)

        return TargetConfig(
            framework=self.framework_id,
            config=config,
            tools=tools,
            mcp_servers=mcp_servers,
            system_prompt=system_prompt,
            files=files,
            metadata={
                "agent_name": agent["name"],
                "workspace_path": agent["path"],
                "config_path": str(workspace / "config.json"),
            },
        )

    def get_config(self, agent: dict) -> dict:
        config_path = Path(agent["path"]) / "config.json"
        if config_path.exists():
            try:
                return json.loads(config_path.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning(f"Failed to read config {config_path}: {exc}")
        return {}

    def list_tools(self, agent: dict) -> list[dict]:
        config = self.get_config(agent)
        return config.get("tools", [])

    def list_mcp_servers(self, agent: dict) -> list[dict]:
        config = self.get_config(agent)
        servers_raw = config.get("servers", {})
        servers: list[dict] = []
        if isinstance(servers_raw, dict):
            for name, server_config in servers_raw.items():
                entry = {"name": name}
                entry.update(server_config)
                servers.append(entry)
        elif isinstance(servers_raw, list):
            servers = servers_raw
        return servers

    def get_system_prompt(self, agent: dict) -> str | None:
        for filename in ("AGENTS.md", "SOUL.md"):
            path = Path(agent["path"]) / filename
            if path.exists():
                try:
                    return path.read_text()
                except OSError:
                    pass
        return None

    def _read_workspace_files(self, workspace: Path) -> dict[str, str]:
        """Read all relevant config files from the workspace."""
        files: dict[str, str] = {}
        patterns = ("*.json", "*.md", "*.yaml", "*.yml", "*.toml")
        for pattern in patterns:
            for path in workspace.glob(pattern):
                if path.is_file():
                    try:
                        files[str(path.relative_to(workspace))] = path.read_text()
                    except OSError:
                        pass
        return files
