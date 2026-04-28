"""
RPR-CONF-002: MCP Tool Permission Declaration Gaps

Detects incomplete, excessive, or inaccurate permission scopes in MCP tool declarations.
Examines scope completeness, least privilege alignment, input schema constraints,
dangerous operation gating, and description accuracy.
"""

from __future__ import annotations

import json
import unicodedata
from urllib.parse import unquote

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


class RprConf002McpPermissionGaps(ReaperCheck):
    """Detect MCP tools with incomplete, excessive, or inaccurate permission scopes."""

    # --- Identity (Contract §2) ---
    check_id = "RPR-CONF-002"
    name = "MCP Tool Permission Declaration Gaps"
    description = (
        "Detects incomplete, excessive, or inaccurate permission scopes in MCP tool declarations. "
        "Examines scope completeness, least privilege alignment, input schema constraints, "
        "dangerous operation gating, and description accuracy. Identifies wildcard permissions, "
        "overprivileged tools, weak input validation, and undocumented capabilities that create security risks."
    )
    contract_version = "1.0"

    # --- Classification (Contract §3) ---
    category = "config"
    wedge = 1
    tier = "community"
    frameworks = ["mcp_generic", "openclaw", "langchain", "crewai"]
    check_type = "deterministic"

    # --- Taxonomy (Contract §4) ---
    taxonomy = TaxonomyMapping(
        primary=TaxonomyEntry(
            framework="owasp_asi",
            entry_id="ASI03",
            justification=(
                "This check directly addresses ASI03 (Supply Chain Compromise) by validating that "
                "MCP tool declarations accurately represent their capabilities and follow least "
                "privilege principles, preventing privilege escalation through misconfigured tool permissions."
            ),
        ),
        secondary=[
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-269",
                justification=(
                    "Improper Privilege Management - tools with excessive scope declarations "
                    "or wildcard permissions violate least privilege principles."
                ),
            ),
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-862",
                justification=(
                    "Missing Authorization - tools with incomplete permission declarations "
                    "may bypass intended access controls."
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

    WILDCARD_SCOPES = {
        "*", "all", ".*", "full-access", "**/*", "admin", "root",
        "any", "full", "unrestricted", "global", "superuser", "everything",
    }

    READ_OPERATIONS = {
        "read", "query", "list", "search", "get", "fetch", "view", "browse", "find"
    }

    WRITE_OPERATIONS = {
        "write", "create", "add", "insert", "post", "save", "store", "update", "modify", "edit", "patch"
    }

    DESTRUCTIVE_OPERATIONS = {
        "delete", "drop", "remove", "truncate", "destroy", "purge", "wipe", "clear",
        "execute", "eval", "run", "exec", "invoke", "admin", "grant", "revoke",
        "eliminate", "terminate", "erase", "expunge", "obliterate", "annihilate", "kill",
        "discard", "dispose", "nullify", "abolish", "scrap", "nuke", "overwrite",
    }

    def detect(self, target: TargetConfig) -> Finding | None:
        """Check MCP tools for permission declaration gaps."""
        
        # Check tools from both mcp_servers and tools fields
        all_tools = []
        
        # Collect tools from mcp_servers
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            server_tools = server.get("tools", [])
            for tool in server_tools:
                tool["_server_name"] = server_name
                all_tools.append(tool)
        
        # Collect tools from direct tools field
        for tool in target.tools:
            all_tools.append(tool)
        
        # Check each tool
        for tool in all_tools:
            result = self._check_tool(tool, target)
            if result:
                return result
        
        return None

    def _check_tool(self, tool: dict, target: TargetConfig) -> Finding | None:
        """Check a single tool for permission declaration issues."""
        tool_name = tool.get("name", "<unnamed>")
        
        # Check 1: Wildcard scope declarations (critical)
        scope = tool.get("scope")
        # Treat empty/whitespace-only strings and empty lists as missing scope
        if isinstance(scope, str) and not scope.strip():
            scope = None
        elif isinstance(scope, list) and len(scope) == 0:
            scope = None
        # Non-standard scope types (bool true, integers) are effectively wildcards
        if scope is not None and not isinstance(scope, (str, list)):
            return self._make_finding(
                tool_name=tool_name,
                issue_type="wildcard_scope",
                observable=f"Tool '{tool_name}' has non-standard scope type ({type(scope).__name__}): {scope}",
                raw_value=f"scope: {scope!r}",
                target=target,
                tool=tool,
                severity="critical"
            )
        if scope is not None:
            if isinstance(scope, str) and self._is_wildcard_scope(scope):
                return self._make_finding(
                    tool_name=tool_name,
                    issue_type="wildcard_scope",
                    observable=f"Tool '{tool_name}' has wildcard scope declaration: '{scope}'",
                    raw_value=f"scope: \"{scope}\"",
                    target=target,
                    tool=tool,
                    severity="critical"
                )
            elif isinstance(scope, list):
                for scope_item in scope:
                    if isinstance(scope_item, str) and self._is_wildcard_scope(scope_item):
                        return self._make_finding(
                            tool_name=tool_name,
                            issue_type="wildcard_scope",
                            observable=f"Tool '{tool_name}' has wildcard scope in list: '{scope_item}'",
                            raw_value=f"scope: {scope}",
                            target=target,
                            tool=tool,
                            severity="critical"
                        )
        
        # Check 2: Missing scope field (high severity)
        if scope is None:
            return self._make_finding(
                tool_name=tool_name,
                issue_type="missing_scope",
                observable=f"Tool '{tool_name}' has no scope declaration",
                raw_value="scope: <missing>",
                target=target,
                tool=tool,
                severity="high"
            )
        
        # Check 3: Scope exceeding operational need
        description = unicodedata.normalize("NFKC", tool.get("description", "")).lower()
        if description:
            described_ops = set()
            for op in self.READ_OPERATIONS:
                if op in description:
                    described_ops.add("read")
                    break
            for op in self.WRITE_OPERATIONS:
                if op in description:
                    described_ops.add("write")
                    break
            for op in self.DESTRUCTIVE_OPERATIONS:
                if op in description:
                    described_ops.add("destructive")
                    break
            
            # If description only mentions read operations but scope includes write/delete
            if described_ops == {"read"} and isinstance(scope, (str, list)):
                scope_str = unicodedata.normalize("NFKC", str(scope)).lower()
                if any(op in scope_str for op in self.WRITE_OPERATIONS | self.DESTRUCTIVE_OPERATIONS):
                    return self._make_finding(
                        tool_name=tool_name,
                        issue_type="excessive_scope",
                        observable=f"Tool '{tool_name}' described as read-only but has write/admin scope",
                        raw_value=f"description mentions read operations but scope: {scope}",
                        target=target,
                        tool=tool,
                        severity="high"
                    )
        
        # Check 4: Weak input schema constraints
        input_schema = (
            tool.get("inputSchema") or tool.get("input_schema")
            or tool.get("args_schema") or tool.get("arguments_schema")
            or tool.get("parameter_schema") or tool.get("parameters_schema")
        )
        if input_schema:
            properties = input_schema.get("properties", {})
            if properties:
                weak_params = []
                for param_name, param_schema in properties.items():
                    constraint_score = self._score_parameter_constraints(param_schema)
                    if constraint_score <= 1:  # Very weak constraints
                        weak_params.append(param_name)
                
                if weak_params:
                    return self._make_finding(
                        tool_name=tool_name,
                        issue_type="weak_input_validation",
                        observable=f"Tool '{tool_name}' has parameters with insufficient constraints: {', '.join(weak_params)}",
                        raw_value=f"parameters {weak_params} lack proper type/enum/range constraints",
                        target=target,
                        tool=tool,
                        severity="medium"
                    )
        
        # Check 5: Destructive operations without confirmation
        if any(op in description for op in self.DESTRUCTIVE_OPERATIONS):
            requires_confirmation = tool.get("requires_confirmation") or tool.get("confirmation_required")
            supports_dry_run = tool.get("supports_dry_run") or tool.get("dry_run_supported")
            
            if not requires_confirmation and not supports_dry_run:
                return self._make_finding(
                    tool_name=tool_name,
                    issue_type="ungated_destructive_ops",
                    observable=f"Tool '{tool_name}' performs destructive operations without confirmation gates",
                    raw_value=f"description contains destructive operations but requires_confirmation: {requires_confirmation}, supports_dry_run: {supports_dry_run}",
                    target=target,
                    tool=tool,
                    severity="high"
                )
        
        return None

    def _is_wildcard_scope(self, value: str) -> bool:
        """Check if a scope value is a wildcard, with Unicode normalization and JSON parsing."""
        # Decode URL encoding (%2A → *) then normalize Unicode (NFKC)
        normalized = unicodedata.normalize("NFKC", unquote(value)).strip().lower()
        if normalized in self.WILDCARD_SCOPES:
            return True

        # Try parsing as JSON to detect nested wildcard permissions
        try:
            parsed = json.loads(value)
            for s in self._extract_strings(parsed):
                if unicodedata.normalize("NFKC", s).strip().lower() in self.WILDCARD_SCOPES:
                    return True
        except (json.JSONDecodeError, TypeError):
            pass

        return False

    @staticmethod
    def _extract_strings(obj: object) -> list[str]:
        """Recursively extract all string values from nested JSON structures."""
        if isinstance(obj, str):
            return [obj]
        if isinstance(obj, dict):
            result = []
            for v in obj.values():
                result.extend(RprConf002McpPermissionGaps._extract_strings(v))
            return result
        if isinstance(obj, list):
            result = []
            for item in obj:
                result.extend(RprConf002McpPermissionGaps._extract_strings(item))
            return result
        return []

    def _score_parameter_constraints(self, param_schema: dict) -> int:
        """Score parameter constraints (0-8 scale)."""
        score = 0
        
        # Type constraint (0-2)
        if "type" in param_schema:
            score += 2
        elif "anyOf" in param_schema or "oneOf" in param_schema:
            score += 1
        
        # Enum constraint (0-2)
        if "enum" in param_schema:
            score += 2
        elif "const" in param_schema:
            score += 1
        
        # Range constraint (0-2)
        if param_schema.get("type") in ["number", "integer"]:
            if "minimum" in param_schema or "maximum" in param_schema:
                score += 1
            if "minimum" in param_schema and "maximum" in param_schema:
                score += 1
        
        # Required constraint (0-1) - checked at parent level, assume present
        score += 1
        
        # Length constraint (0-1)
        if param_schema.get("type") == "string":
            if "maxLength" in param_schema or "minLength" in param_schema or "pattern" in param_schema:
                score += 1
        
        return min(score, 8)

    def _make_finding(
        self,
        tool_name: str,
        issue_type: str,
        observable: str,
        raw_value: str,
        target: TargetConfig,
        tool: dict,
        severity: str = None,
    ) -> Finding:
        """Create a standardized finding for permission declaration gaps."""
        
        # Determine file path based on framework
        file_path = None
        if target.framework == "openclaw":
            file_path = target.metadata.get("config_path", "~/.openclaw/config.json")
        elif target.framework == "langchain":
            file_path = target.metadata.get("config_path", "agent_config.py")
        elif target.framework == "crewai":
            file_path = target.metadata.get("config_path", "crew_config.yaml")
        
        return Finding(
            check_id=self.check_id,
            severity=severity or self.severity.default,
            confidence="high",
            evidence=Evidence(
                observable=observable,
                file_path=file_path,
                line=None,
                line_end=None,
                raw_value=raw_value,
                context={
                    "tool_name": tool_name,
                    "issue_type": issue_type,
                    "server_name": tool.get("_server_name", ""),
                },
            ),
            remediation=Remediation(
                description=(
                    "Replace wildcard scopes with specific capabilities, add comprehensive input schema constraints, "
                    "gate dangerous operations with confirmation requirements, and ensure tool descriptions accurately "
                    "reflect all capabilities. Follow least privilege principles for tool permission declarations."
                ),
                steps={
                    "mcp_generic": (
                        'Update MCP tool declarations:\n'
                        '1. Replace scope: "*" with specific capabilities like scope: ["read:documents", "write:files"]\n'
                        '2. Add complete inputSchema with type constraints:\n'
                        '   "inputSchema": {\n'
                        '     "type": "object",\n'
                        '     "properties": {\n'
                        '       "filename": {"type": "string", "maxLength": 255},\n'
                        '       "mode": {"type": "string", "enum": ["read", "write"]}\n'
                        '     },\n'
                        '     "required": ["filename", "mode"],\n'
                        '     "additionalProperties": false\n'
                        '   }\n'
                        '3. For destructive operations, add: "requires_confirmation": true\n'
                        '4. Update descriptions to accurately reflect all tool capabilities'
                    ),
                    "openclaw": (
                        'In OpenClaw skill definitions:\n'
                        '1. Edit skill YAML to add explicit scope field:\n'
                        '   scope:\n'
                        '     - read:workspace\n'
                        '     - write:files\n'
                        '2. Enhance input_schema with proper constraints:\n'
                        '   input_schema:\n'
                        '     type: object\n'
                        '     properties:\n'
                        '       path:\n'
                        '         type: string\n'
                        '         maxLength: 500\n'
                        '         pattern: "^[a-zA-Z0-9._/-]+$"\n'
                        '     required: [path]\n'
                        '     additionalProperties: false\n'
                        '3. Add requires_confirmation: true for destructive skills'
                    ),
                    "langchain": (
                        'Update StructuredTool definitions:\n'
                        '1. Complete args_schema with comprehensive constraints:\n'
                        '   from pydantic import BaseModel, Field\n'
                        '   class ToolArgs(BaseModel):\n'
                        '       filename: str = Field(..., max_length=255, regex="^[\\w.-]+$")\n'
                        '       operation: str = Field(..., regex="^(read|write)$")\n'
                        '2. Split overprivileged tools into focused, single-purpose tools\n'
                        '3. Add scope validation in tool implementation\n'
                        '4. For dangerous operations, implement confirmation prompts'
                    ),
                    "crewai": (
                        'Define per-agent tool access restrictions:\n'
                        '1. In crew configuration, specify explicit tool lists:\n'
                        '   agents:\n'
                        '     - name: research_agent\n'
                        '       tools: [web_search, document_read]  # No write tools\n'
                        '     - name: writer_agent\n'
                        '       tools: [document_write, file_save]\n'
                        '2. Remove allow_delegation: true unless specifically required\n'
                        '3. Document all tool capabilities in agent descriptions\n'
                        '4. Implement tool-level permission checks in custom tools'
                    ),
                },
                references=[
                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/",
                ],
                effort="low",
            ),
            taxonomy=self.taxonomy,
        )