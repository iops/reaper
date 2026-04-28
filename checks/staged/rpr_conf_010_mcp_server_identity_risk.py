"""
RPR-CONF-010: MCP Server Identity Confusion Risk

Detects MCP configurations vulnerable to server identity confusion attacks.
Identifies namespace collisions where multiple MCP servers expose tools with
identical or similar names, creating opportunities for call misrouting,
response attribution spoofing, and cross-server capability claiming attacks.
"""

from __future__ import annotations

from reaper.sdk import (
    Evidence,
    Finding,
    ReaperCheck,
    Remediation,
    SeverityRating,
    TargetConfig,
    TaxonomyEntry,
    TaxonomyMapping,
)


class RprConf010McpServerIdentityRisk(ReaperCheck):
    """Detect MCP server identity confusion vulnerabilities."""

    # --- Identity (Contract §2) ---
    check_id = "RPR-CONF-010"
    name = "MCP Server Identity Confusion Risk"
    description = (
        "Detects MCP configurations vulnerable to server identity confusion attacks. "
        "Identifies namespace collisions where multiple MCP servers expose tools with "
        "identical or similar names, creating opportunities for call misrouting, "
        "response attribution spoofing, and cross-server capability claiming attacks."
    )
    contract_version = "1.0"

    # --- Classification (Contract §3) ---
    category = "config"
    wedge = 1
    tier = "community"
    frameworks = ["mcp_generic", "openclaw", "langchain", "crewai", "autogen"]
    check_type = "deterministic"

    # --- Taxonomy (Contract §4) ---
    taxonomy = TaxonomyMapping(
        primary=TaxonomyEntry(
            framework="owasp_asi",
            entry_id="ASI07",
            justification=(
                "This check detects security control weaknesses in MCP server "
                "identity management that enable server impersonation and trust "
                "boundary violations, directly mapping to ASI07's focus on "
                "security control failures."
            ),
        ),
        secondary=[
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-668",
                justification=(
                    "Namespace collisions and identity confusion represent exposure "
                    "of resources to the wrong sphere, allowing unintended access patterns."
                ),
            ),
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-284",
                justification=(
                    "Improper access control when multiple servers can respond to "
                    "the same tool name without proper disambiguation."
                ),
            ),
        ],
    )

    # --- Severity (Contract §5) ---
    severity = SeverityRating(
        default="high",
        cvss_base=7.5,
        aarf=None,
    )

    # --- Detection Logic (Contract §6) ---

    # Generic tool names that are high-risk for collisions
    GENERIC_TOOL_NAMES = {
        "search", "query", "get", "send", "fetch", "find", "read", "write",
        "create", "update", "delete", "list", "execute", "run", "call",
        "request", "post", "put", "patch", "retrieve", "save", "load"
    }

    def detect(self, target: TargetConfig) -> Finding | None:
        """Check for MCP server identity confusion vulnerabilities."""
        
        # Need at least 2 MCP servers for identity confusion
        if len(target.mcp_servers) < 2:
            return None

        # Extract tool names for each server
        server_tools = {}
        all_tool_names = []
        
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            tool_names = self._extract_tool_names(server, target)
            server_tools[server_name] = tool_names
            all_tool_names.extend(tool_names)

        # Check for exact name collisions
        exact_collision = self._find_exact_collisions(server_tools)
        if exact_collision:
            return self._make_finding(
                collision_type="exact",
                details=exact_collision,
                target=target
            )

        # Check for similar name collisions (edit distance <= 2)
        similar_collision = self._find_similar_collisions(server_tools)
        if similar_collision:
            return self._make_finding(
                collision_type="similar",
                details=similar_collision,
                target=target
            )

        # Check for generic name collisions across multiple servers
        generic_collision = self._find_generic_collisions(server_tools)
        if generic_collision:
            return self._make_finding(
                collision_type="generic",
                details=generic_collision,
                target=target
            )

        return None

    def _extract_tool_names(self, server: dict, target: TargetConfig) -> list[str]:
        """Extract tool names exposed by a specific MCP server."""
        tool_names = []
        server_name = server.get("name", "")

        # Method 1: Direct tools declaration in server config
        if "tools" in server:
            for tool in server["tools"]:
                if isinstance(tool, dict) and "name" in tool:
                    tool_names.append(tool["name"])
                elif isinstance(tool, str):
                    tool_names.append(tool)

        # Method 2: Check global tools list for server-specific tools
        for tool in target.tools:
            if isinstance(tool, dict):
                tool_name = tool.get("name", "")
                # Check if tool belongs to this server
                tool_server = tool.get("server", tool.get("source", ""))
                if tool_server == server_name and tool_name:
                    tool_names.append(tool_name)

        # Method 3: Look for capabilities or schema declarations
        capabilities = server.get("capabilities", {})
        if isinstance(capabilities, dict):
            tools_cap = capabilities.get("tools", {})
            if isinstance(tools_cap, dict):
                for tool_name in tools_cap.keys():
                    tool_names.append(tool_name)

        # Method 4: Check for tool patterns in server command/args
        command = server.get("command", "")
        if isinstance(command, str) and "tool" in command.lower():
            # Extract potential tool names from command patterns
            if "search" in command.lower():
                tool_names.append("search")
            if "query" in command.lower():
                tool_names.append("query")

        return list(set(tool_names))  # Remove duplicates

    def _find_exact_collisions(self, server_tools: dict[str, list[str]]) -> dict | None:
        """Find exact tool name collisions between servers."""
        tool_to_servers = {}
        
        for server, tools in server_tools.items():
            for tool in tools:
                if tool not in tool_to_servers:
                    tool_to_servers[tool] = []
                tool_to_servers[tool].append(server)

        # Find tools exposed by multiple servers
        for tool, servers in tool_to_servers.items():
            if len(servers) > 1:
                return {
                    "tool_name": tool,
                    "servers": servers,
                    "collision_type": "exact"
                }

        return None

    def _find_similar_collisions(self, server_tools: dict[str, list[str]]) -> dict | None:
        """Find similar tool names (edit distance <= 2) across servers."""
        all_tools = []
        for server, tools in server_tools.items():
            for tool in tools:
                all_tools.append((tool, server))

        # Check all pairs for similarity
        for i, (tool1, server1) in enumerate(all_tools):
            for tool2, server2 in all_tools[i+1:]:
                if server1 != server2 and self._edit_distance(tool1, tool2) <= 2 and tool1 != tool2:
                    return {
                        "tool1": tool1,
                        "server1": server1,
                        "tool2": tool2,
                        "server2": server2,
                        "collision_type": "similar",
                        "edit_distance": self._edit_distance(tool1, tool2)
                    }

        return None

    def _find_generic_collisions(self, server_tools: dict[str, list[str]]) -> dict | None:
        """Find generic tool names appearing across multiple servers."""
        generic_tools_found = {}
        
        for server, tools in server_tools.items():
            for tool in tools:
                if tool.lower() in self.GENERIC_TOOL_NAMES:
                    if tool not in generic_tools_found:
                        generic_tools_found[tool] = []
                    generic_tools_found[tool].append(server)

        # Find generic tools on multiple servers
        for tool, servers in generic_tools_found.items():
            if len(servers) > 1:
                return {
                    "tool_name": tool,
                    "servers": servers,
                    "collision_type": "generic"
                }

        return None

    def _edit_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._edit_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _make_finding(
        self,
        collision_type: str,
        details: dict,
        target: TargetConfig,
    ) -> Finding:
        """Create a finding for the detected identity confusion vulnerability."""
        
        if collision_type == "exact":
            observable = f"Multiple MCP servers expose identical tool name '{details['tool_name']}'"
            raw_value = f"Tool '{details['tool_name']}' exposed by servers: {', '.join(details['servers'])}"
        elif collision_type == "similar":
            observable = f"MCP servers expose similar tool names: '{details['tool1']}' and '{details['tool2']}'"
            raw_value = f"Tool name collision: '{details['tool1']}' (server: {details['server1']}) vs '{details['tool2']}' (server: {details['server2']}) - edit distance: {details['edit_distance']}"
        else:  # generic
            observable = f"Multiple MCP servers expose generic tool name '{details['tool_name']}'"
            raw_value = f"Generic tool '{details['tool_name']}' exposed by servers: {', '.join(details['servers'])}"

        return Finding(
            check_id=self.check_id,
            severity=self.severity.default,
            confidence="high",
            evidence=Evidence(
                observable=observable,
                file_path=self._resolve_config_path(target),
                line=None,
                line_end=None,
                raw_value=raw_value,
                context={
                    "collision_type": collision_type,
                    "server_count": str(len(target.mcp_servers)),
                    "framework": target.framework,
                },
            ),
            remediation=Remediation(
                description=(
                    "Implement server-namespaced tool identifiers and strict tool "
                    "routing based on server identity. Use prefixed tool names "
                    "(server.tool_name) and validate server identity before routing calls."
                ),
                steps={
                    "mcp_generic": (
                        'Implement server-namespaced tool names:\n'
                        '1. Prefix all tool names with server identifier: "server_name.tool_name"\n'
                        '2. Implement fixed tool routing registry that maps namespaced names to servers\n'
                        '3. Add server identity validation before dispatching tool calls\n'
                        '4. Track data provenance by tagging responses with source server'
                    ),
                    "openclaw": (
                        'In ~/.openclaw/config.json, implement tool namespacing:\n'
                        '1. Update tool registry to use "server.tool" naming pattern\n'
                        '2. Configure ToolRouter with immutable server-to-tool mapping\n'
                        '3. Add server validation middleware in tool dispatch pipeline\n'
                        '4. Enable provenance tracking in tool response metadata'
                    ),
                    "langchain": (
                        'Configure server-prefixed tool names when binding MCP tools:\n'
                        '```python\n'
                        'from langchain.tools import Tool\n'
                        'tool = Tool(\n'
                        '    name=f"{server_name}.{tool_name}",\n'
                        '    description=tool_description,\n'
                        '    func=tool_function\n'
                        ')\n'
                        '```\n'
                        'Implement custom ToolOutputParser to tag responses with server identity.'
                    ),
                    "crewai": (
                        'Register tools with server namespace in agent configuration:\n'
                        '```python\n'
                        'tools = [\n'
                        '    Tool(\n'
                        '        name=f"{server_name}_{tool_name}",\n'
                        '        description=f"{tool_desc} (via {server_name})",\n'
                        '        func=tool_function\n'
                        '    )\n'
                        ']\n'
                        '```\n'
                        'Implement tool routing agent to validate server identity before dispatch.'
                    ),
                    "autogen": (
                        'Configure namespaced tools in agent setup:\n'
                        '```python\n'
                        'tools = {\n'
                        '    f"{server_name}.{tool_name}": {\n'
                        '        "function": tool_function,\n'
                        '        "server": server_name\n'
                        '    }\n'
                        '}\n'
                        '```\n'
                        'Add server validation in tool execution middleware.'
                    ),
                },
                references=[
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                    "https://github.com/modelcontextprotocol/specification",
                ],
                effort="medium",
            ),
            taxonomy=self.taxonomy,
        )

    def _resolve_config_path(self, target: TargetConfig) -> str | None:
        """Resolve the MCP server config file path for this framework."""
        if target.framework == "openclaw":
            return target.metadata.get("config_path", "~/.openclaw/config.json")
        elif target.framework == "langchain":
            return target.metadata.get("config_path", "langchain_config.py")
        elif target.framework == "crewai":
            return target.metadata.get("config_path", "crew_config.py")
        elif target.framework == "autogen":
            return target.metadata.get("config_path", "autogen_config.py")
        return "mcp_config.json"