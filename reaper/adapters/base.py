"""
Base framework adapter interface.

Every adapter implements this interface to let the engine discover
agent instances and extract their configuration into TargetConfig objects.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from reaper.sdk import ProbeTarget, TargetConfig


class FrameworkAdapter(ABC):
    """Abstract base for all framework adapters."""

    # The canonical framework identifier (must match CANONICAL_FRAMEWORKS in sdk.py)
    framework_id: str = ""

    @abstractmethod
    def discover_agents(self, search_path: str) -> list[dict]:
        """
        Find agent instances under search_path.

        Returns a list of agent descriptors (dicts with at minimum
        'name' and 'path' keys). The engine passes these back to
        build_target() one at a time.
        """

    @abstractmethod
    def build_target(self, agent: dict) -> TargetConfig:
        """
        Build a TargetConfig from a discovered agent descriptor.

        Reads config files, tool definitions, MCP server declarations,
        and system prompts for the given agent.
        """

    def get_config(self, agent: dict) -> dict:
        """Extract raw configuration dict for an agent."""
        return {}

    def list_tools(self, agent: dict) -> list[dict]:
        """Enumerate tools available to the agent."""
        return []

    def list_mcp_servers(self, agent: dict) -> list[dict]:
        """Enumerate MCP server declarations for the agent."""
        return []

    def get_system_prompt(self, agent: dict) -> str | None:
        """Extract the system prompt / workspace instructions."""
        return None

    def discover_probe_targets(
        self, agent: dict, target: TargetConfig
    ) -> list[ProbeTarget]:
        """Discover probeable MCP endpoints from a discovered agent.

        Returns ProbeTargets for MCP servers that can be actively probed.
        Override in adapters that support Wedge 2 probing.
        """
        return []
