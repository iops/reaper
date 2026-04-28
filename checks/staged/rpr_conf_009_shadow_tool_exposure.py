"""
RPR-CONF-009: Shadow Tool Exposure Detection

Detects MCP server tools that are exposed but not referenced in the agent's
system prompt or intended configuration. These shadow tools create excessive
agency attack surface because they lack proper oversight, monitoring, and
human-in-the-loop controls that were never designed for undeclared capabilities.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from reaper.sdk import (
    AARFAssessment,
    Evidence,
    Finding,
    ReaperCheck,
    Remediation,
    SeverityRating,
    TargetConfig,
    TaxonomyEntry,
    TaxonomyMapping,
)


class RprConf009ShadowToolExposure(ReaperCheck):
    """Detect MCP server tools that lack system prompt references."""

    # --- Identity (Contract §2) ---
    check_id = "RPR-CONF-009"
    name = "Shadow Tool Exposure Detection"
    description = (
        "Detects MCP server tools that are exposed but not referenced in the agent's "
        "system prompt or intended configuration. These shadow tools create excessive "
        "agency attack surface because they lack proper oversight, monitoring, and "
        "human-in-the-loop controls that were never designed for undeclared capabilities."
    )
    contract_version = "1.0"

    # --- Classification (Contract §3) ---
    category = "config"
    wedge = 1
    tier = "community"
    frameworks = ["universal"]
    check_type = "deterministic"

    # --- Taxonomy (Contract §4) ---
    taxonomy = TaxonomyMapping(
        primary=TaxonomyEntry(
            framework="owasp_asi",
            entry_id="ASI03",
            justification=(
                "Shadow tools represent excessive agency - capabilities beyond the intended "
                "scope that create ungoverned attack surface, directly mapping to ASI03's "
                "focus on excessive agency vulnerabilities."
            ),
        ),
        secondary=[
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-862",
                justification=(
                    "Missing authorization controls for undeclared tools that should "
                    "require explicit approval."
                ),
            ),
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-269",
                justification=(
                    "Improper privilege management where agent gains access to "
                    "unintended capabilities."
                ),
            ),
        ],
    )

    # --- Severity (Contract §5) ---
    severity = SeverityRating(
        default="critical",
        cvss_base=8.5,
        aarf=AARFAssessment(
            autonomy=1.0,
            tools=1.0,
            language=1.0,
            context=0.5,
            non_determinism=0.5,
            opacity=1.0,
            persistence=0.5,
            identity=0.5,
            multi_agent=0.0,
            self_modification=0.0,
        ),
    )

    # --- Detection Logic (Contract §6) ---

    # All possible field names where tools might be defined in MCP servers
    TOOL_FIELD_NAMES = {
        "tools", "tool", "functions", "function", "commands", "command",
        "actions", "action", "capabilities", "capability", "methods", "method",
        "operations", "operation", "handlers", "handler", "endpoints", "endpoint",
        "services", "service", "apis", "api", "procedures", "procedure",
        "interfaces", "interface", "registry", "catalog", "manifest",
        "available", "enabled", "exposed", "public", "callable"
    }

    def detect(self, target: TargetConfig) -> Finding | None:
        """Check for shadow tools in MCP server configurations."""
        # Extract all tools from MCP servers using comprehensive search
        mcp_tools = self._extract_all_mcp_tools(target.mcp_servers)
        if not mcp_tools:
            return None

        # Extract declared tools from system prompt and config
        declared_tools = self._extract_declared_tools(target)

        # Find shadow tools - MCP tools not declared in system prompt/config
        shadow_tools = self._find_shadow_tools(mcp_tools, declared_tools)
        
        if not shadow_tools:
            return None

        # Return finding for the first shadow tool detected
        shadow_tool = shadow_tools[0]
        return self._make_finding(shadow_tool, shadow_tools, target)

    def _extract_all_mcp_tools(self, mcp_servers: list[dict]) -> list[dict]:
        """Extract all tools from MCP servers using recursive search."""
        all_tools = []
        
        for i, server in enumerate(mcp_servers):
            server_name = server.get("name", f"server_{i}")
            tools = self._recursive_tool_search(server, server_name)
            all_tools.extend(tools)
            
        return all_tools

    def _recursive_tool_search(self, obj: Any, server_name: str, path: str = "") -> list[dict]:
        """Recursively search for tools in nested structures."""
        tools = []
        
        if isinstance(obj, dict):
            # Check all keys for tool-related fields
            for key, value in obj.items():
                key_lower = key.lower()
                current_path = f"{path}.{key}" if path else key
                
                # Direct tool field match
                if key_lower in self.TOOL_FIELD_NAMES:
                    extracted = self._extract_tools_from_value(value, server_name, current_path)
                    tools.extend(extracted)
                
                # Recursively search nested objects
                nested_tools = self._recursive_tool_search(value, server_name, current_path)
                tools.extend(nested_tools)
                
        elif isinstance(obj, list):
            # Search each item in the list
            for i, item in enumerate(obj):
                item_path = f"{path}[{i}]" if path else f"[{i}]"
                nested_tools = self._recursive_tool_search(item, server_name, item_path)
                tools.extend(nested_tools)
                
        return tools

    def _extract_tools_from_value(self, value: Any, server_name: str, path: str) -> list[dict]:
        """Extract tool names from various value formats."""
        tools = []
        
        if isinstance(value, list):
            for i, item in enumerate(value):
                item_path = f"{path}[{i}]"
                tool_name = self._extract_tool_name(item)
                if tool_name:
                    tools.append({
                        "name": tool_name,
                        "server": server_name,
                        "path": item_path,
                        "raw": item
                    })
                    
        elif isinstance(value, dict):
            # Handle single tool object or nested tool structures
            tool_name = self._extract_tool_name(value)
            if tool_name:
                tools.append({
                    "name": tool_name,
                    "server": server_name,
                    "path": path,
                    "raw": value
                })
            # Also recursively search the dict for more tools
            nested_tools = self._recursive_tool_search(value, server_name, path)
            tools.extend(nested_tools)
            
        elif isinstance(value, str):
            # Handle string tool names or comma-separated lists
            tool_names = self._parse_string_tools(value)
            for j, tool_name in enumerate(tool_names):
                tools.append({
                    "name": tool_name,
                    "server": server_name,
                    "path": f"{path}[{j}]" if len(tool_names) > 1 else path,
                    "raw": tool_name
                })
                
        return tools

    def _extract_tool_name(self, item: Any) -> str | None:
        """Extract tool name from various item formats."""
        if isinstance(item, str):
            # String tool name
            normalized = self._normalize_tool_name(item.strip())
            return normalized if normalized else None
            
        elif isinstance(item, dict):
            # Try common tool name fields
            name_fields = [
                "name", "function", "tool", "command", "action",
                "method", "operation", "handler", "endpoint", "id",
                "identifier", "key", "title", "label", "type"
            ]
            
            for field in name_fields:
                if field in item and isinstance(item[field], str):
                    normalized = self._normalize_tool_name(item[field].strip())
                    if normalized:
                        return normalized
                        
        return None

    def _parse_string_tools(self, value: str) -> list[str]:
        """Parse tool names from string values (comma-separated, etc.)."""
        # Split on common delimiters
        separators = [",", ";", "|", " ", "\n", "\t"]
        parts = [value]
        
        for sep in separators:
            new_parts = []
            for part in parts:
                new_parts.extend(part.split(sep))
            parts = new_parts
            
        # Clean and normalize
        tools = []
        for part in parts:
            normalized = self._normalize_tool_name(part.strip())
            if normalized:
                tools.append(normalized)
                
        return tools

    def _normalize_tool_name(self, name: str) -> str:
        """Normalize tool names for consistent comparison."""
        if not name:
            return ""
            
        # Unicode normalization to prevent homoglyph attacks
        normalized = unicodedata.normalize('NFKD', name)
        
        # Remove common prefixes/suffixes
        prefixes = ["tool_", "cmd_", "action_", "func_", "method_"]
        suffixes = ["_tool", "_cmd", "_action", "_func", "_method", "_handler"]
        
        name_lower = normalized.lower()
        for prefix in prefixes:
            if name_lower.startswith(prefix):
                normalized = normalized[len(prefix):]
                break
                
        for suffix in suffixes:
            if name_lower.endswith(suffix):
                normalized = normalized[:-len(suffix)]
                break
                
        return normalized.strip()

    def _extract_declared_tools(self, target: TargetConfig) -> set[str]:
        """Extract tool names declared in system prompt and config."""
        declared = set()
        
        # Extract from system prompt
        if target.system_prompt:
            prompt_tools = self._extract_tools_from_text(target.system_prompt)
            declared.update(prompt_tools)
            
        # Extract from explicit tools list
        for tool in target.tools:
            if isinstance(tool, dict) and "name" in tool:
                normalized = self._normalize_tool_name(tool["name"])
                if normalized:
                    declared.add(normalized)
                    
        # Extract from config using same recursive search
        config_tools = self._recursive_tool_search(target.config, "config")
        for tool in config_tools:
            declared.add(tool["name"])
            
        return declared

    def _extract_tools_from_text(self, text: str) -> set[str]:
        """Extract tool names from text using multiple strategies."""
        tools = set()
        text_lower = text.lower()
        
        # Strategy 1: Code blocks and function calls
        patterns = [
            # Function call patterns
            r'(?:call|invoke|use|execute)\s+(\w+)\s*\(',
            r'(\w+)\s*\(',
            # Tool references
            r'(?:tool|function|command|action)\s+(?:named\s+)?["\']?(\w+)["\']?',
            # Capability descriptions
            r'I\s+can\s+(?:use\s+)?["\']?(\w+)["\']?(?:\s+to|\s+for)',
            r'available\s+(?:tools?|functions?|commands?):\s*([^\n.]+)',
            # Direct mentions
            r'\b(\w+_tool|\w+_cmd|\w+_func)\b',
            r'\btool_(\w+)\b',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if len(match.groups()) >= 1:
                    tool_text = match.group(1).strip()
                    # Handle comma-separated lists in capability descriptions
                    if ',' in tool_text:
                        for item in tool_text.split(','):
                            normalized = self._normalize_tool_name(item.strip())
                            if normalized:
                                tools.add(normalized)
                    else:
                        normalized = self._normalize_tool_name(tool_text)
                        if normalized:
                            tools.add(normalized)
        
        # Strategy 2: Extract potential tool names from any word that looks like a tool
        words = re.findall(r'\b\w+\b', text_lower)
        for word in words:
            # Common tool name patterns
            if (word.endswith('_tool') or word.endswith('_cmd') or 
                word.endswith('_func') or word.endswith('_action') or
                word.startswith('tool_') or word.startswith('cmd_') or
                word.startswith('func_') or word.startswith('action_')):
                normalized = self._normalize_tool_name(word)
                if normalized:
                    tools.add(normalized)
        
        return tools

    def _find_shadow_tools(self, mcp_tools: list[dict], declared_tools: set[str]) -> list[dict]:
        """Find MCP tools that are not declared in system prompt or config."""
        shadow_tools = []
        
        for tool in mcp_tools:
            tool_name = tool["name"]
            
            # Check if tool is declared (case-insensitive, normalized comparison)
            is_declared = False
            for declared in declared_tools:
                if self._tools_match(tool_name, declared):
                    is_declared = True
                    break
                    
            if not is_declared:
                shadow_tools.append(tool)
                
        return shadow_tools

    def _tools_match(self, tool1: str, tool2: str) -> bool:
        """Check if two tool names match using fuzzy matching."""
        if not tool1 or not tool2:
            return False
            
        # Exact match (case-insensitive)
        if tool1.lower() == tool2.lower():
            return True
            
        # Normalized comparison
        norm1 = self._normalize_tool_name(tool1).lower()
        norm2 = self._normalize_tool_name(tool2).lower()
        
        if norm1 == norm2:
            return True
            
        # Substring matching for partial references
        if norm1 in norm2 or norm2 in norm1:
            return True
            
        # Common word matching (for descriptive tool names)
        words1 = set(re.findall(r'\w+', norm1.lower()))
        words2 = set(re.findall(r'\w+', norm2.lower()))
        
        # Significant word overlap
        if words1 and words2 and len(words1.intersection(words2)) > 0:
            overlap_ratio = len(words1.intersection(words2)) / min(len(words1), len(words2))
            if overlap_ratio >= 0.5:  # At least 50% word overlap
                return True
                
        return False

    def _make_finding(self, shadow_tool: dict, all_shadows: list[dict], target: TargetConfig) -> Finding:
        """Create a finding for the detected shadow tool."""
        tool_name = shadow_tool["name"]
        server_name = shadow_tool["server"]
        tool_path = shadow_tool["path"]
        
        shadow_count = len(all_shadows)
        shadow_list = ", ".join(f'"{t["name"]}"' for t in all_shadows[:5])
        if shadow_count > 5:
            shadow_list += f" and {shadow_count - 5} more"
            
        return Finding(
            check_id=self.check_id,
            severity=self.severity.default,
            confidence="high",
            evidence=Evidence(
                observable=(
                    f'MCP server "{server_name}" exposes tool "{tool_name}" not referenced '
                    f"in system prompt or configuration. {shadow_count} shadow tools detected: {shadow_list}"
                ),
                file_path=self._resolve_config_path(target, server_name),
                line=None,
                line_end=None,
                raw_value=f'{tool_path}: {shadow_tool["raw"]}',
                context={
                    "mcp_server": server_name,
                    "shadow_tool": tool_name,
                    "tool_path": tool_path,
                    "shadow_count": str(shadow_count),
                },
            ),
            remediation=Remediation(
                description=(
                    "Implement explicit tool allowlisting at MCP server level to restrict "
                    "callable tools to only those referenced in the system prompt. Remove "
                    "undeclared tools from MCP server configurations or add explicit references "
                    "to them in the agent's system prompt and documentation."
                ),
                steps={
                    "universal": (
                        f'1. Review MCP server "{server_name}" configuration and remove undeclared tools:\n'
                        f'   - Located at: {tool_path}\n'
                        f'   - Shadow tool: "{tool_name}"\n\n'
                        '2. If the tool is needed, add explicit reference in system prompt:\n'
                        f'   "I can use the {tool_name} tool to [describe capability]"\n\n'
                        '3. Implement tool allowlisting in MCP server config:\n'
                        '   {\n'
                        '     "allowed_tools": ["tool1", "tool2"],\n'
                        '     "deny_unlisted": true\n'
                        '   }\n\n'
                        '4. Add monitoring for calls to non-allowlisted tools.'
                    ),
                },
                references=[
                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/",
                    "https://atlas.mitre.org/techniques/AML.T0098",
                ],
                effort="low",
            ),
            taxonomy=self.taxonomy,
        )

    def _resolve_config_path(self, target: TargetConfig, server_name: str) -> str | None:
        """Resolve the configuration file path for the MCP server."""
        if target.framework == "openclaw":
            return target.metadata.get("config_path", "~/.openclaw/config.json")
        elif "config_path" in target.metadata:
            return target.metadata["config_path"]
        return f"mcp_server_{server_name}_config"