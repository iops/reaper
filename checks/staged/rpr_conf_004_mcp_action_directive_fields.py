"""
RPR-CONF-004: MCP Tool Response Schema Action-Directive Fields

Detects action-directive fields in MCP server tool response schemas that create 
instruction channels allowing MCP servers to inject tool call instructions 
directly into agent processing flow. These fields bypass prompt-layer defenses 
by providing a designed instruction vector rather than exploiting an existing one.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

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


class RprConf004McpActionDirectiveFields(ReaperCheck):
    """Detect action-directive fields in MCP tool response schemas."""

    # --- Identity (Contract §2) ---
    check_id = "RPR-CONF-004"
    name = "MCP Tool Response Schema Action-Directive Fields"
    description = (
        "Detects action-directive fields in MCP server tool response schemas that "
        "create instruction channels allowing MCP servers to inject tool call "
        "instructions directly into agent processing flow. These fields bypass "
        "prompt-layer defenses by providing a designed instruction vector rather "
        "than exploiting an existing one. Critical when combined with dynamic "
        "population and auto-execution frameworks."
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
            entry_id="ASI04",
            justification=(
                "This check detects architectural instruction vectors in MCP tool "
                "schemas that enable supply chain attacks by allowing external "
                "components to inject instructions, representing a fundamental "
                "trust boundary violation in agent architecture."
            ),
        ),
        secondary=[
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-912",
                justification=(
                    "Hidden functionality in response schemas that enables "
                    "instruction injection represents hidden backdoor functionality."
                ),
            ),
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-862",
                justification=(
                    "Action-directive fields bypass authorization by providing a "
                    "direct instruction channel that circumvents agent "
                    "decision-making processes."
                ),
            ),
        ],
    )

    # --- Severity (Contract §5) ---
    severity = SeverityRating(
        default="critical",
        cvss_base=8.5,
        aarf=None,
    )

    # --- Detection Logic (Contract §6) ---

    # Primary patterns (auto-flag) - exact matches after normalization
    PRIMARY_PATTERNS = {
        "recommended_actions", "next_steps", "follow_up_tasks", "instructions",
        "agent_instructions", "agent_actions", "suggested_actions", "required_actions",
        "pending_actions", "action_items", "todo", "tasks", "commands", "directives",
        # Common variations
        "action_plan", "step_sequence", "workflow_items", "procedure_steps",
        "execution_steps", "operation_sequence", "command_list", "directive_list",
        "task_queue", "action_queue", "steps_to_follow", "what_to_do_next",
        "recommended_next_steps", "suggested_next_actions", "follow_up_actions",
        # Numbered and suffixed variants
        "tasks1", "tasks2", "actions1", "actions2", "steps1", "steps2",
        "actions_v1", "actions_v2", "tasks_v1", "tasks_v2", "instructions_list",
        "actions_list", "tasks_list", "commands_list", "directives_list",
        "next_steps_list", "follow_up_list", "todo_list", "action_items_list",
    }

    # Secondary patterns (flag for review) - need context analysis
    SECONDARY_PATTERNS = {
        "notes", "guidance", "recommendations", "metadata", "response",
        "hints", "suggestions", "advice", "tips", "help", "info",
        "processing_notes", "execution_notes", "operation_notes",
        "workflow_guidance", "procedure_guidance", "step_guidance",
    }

    # Common schema locations to check
    SCHEMA_LOCATIONS = [
        # Direct response schema
        "response", "result", "output", "return", "data",
        # Framework-specific locations
        "outputFormat", "return_schema", "result_schema", "response_schema",
        "output_schema", "schema", "properties", "items", "content",
        # Nested locations
        "metadata", "context", "details", "extra", "additional",
    ]

    # Instructional description keywords
    INSTRUCTIONAL_KEYWORDS = {
        "action", "should", "must", "agent", "next", "follow", "execute",
        "perform", "run", "call", "invoke", "trigger", "do", "steps",
        "sequence", "procedure", "workflow", "process", "command", "directive",
        "instruction", "task", "todo", "operation", "job", "activity",
    }

    def detect(self, target: TargetConfig) -> Finding | None:
        """Check MCP server tools for action-directive fields in response schemas."""
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            tools = server.get("tools", [])
            
            for tool in tools:
                tool_name = tool.get("name", "<unnamed>")
                
                # Check all possible schema locations
                for schema_location in self._get_schema_locations(tool):
                    finding = self._check_schema_for_directives(
                        server_name, tool_name, schema_location["schema"], 
                        schema_location["path"], target
                    )
                    if finding:
                        return finding

        return None

    def _get_schema_locations(self, tool: dict) -> list[dict]:
        """Extract all possible response schema locations from a tool definition."""
        locations = []
        
        # Main response schema locations
        for loc in ["response", "result", "output", "return", "outputFormat", "schema"]:
            if loc in tool:
                locations.append({"schema": tool[loc], "path": f"tools.{tool.get('name', '<unnamed>')}.{loc}"})
        
        # Check inputSchema for response-related fields (some tools define response format here)
        input_schema = tool.get("inputSchema", {})
        if isinstance(input_schema, dict):
            for prop_name, prop_schema in input_schema.get("properties", {}).items():
                if self._is_response_related_property(prop_name):
                    locations.append({
                        "schema": prop_schema, 
                        "path": f"tools.{tool.get('name', '<unnamed>')}.inputSchema.properties.{prop_name}"
                    })
        
        # Check nested definitions
        for key, value in tool.items():
            if isinstance(value, dict) and "properties" in value:
                locations.append({"schema": value, "path": f"tools.{tool.get('name', '<unnamed>')}.{key}"})
        
        return locations

    def _is_response_related_property(self, prop_name: str) -> bool:
        """Check if a property name suggests it's related to response formatting."""
        normalized = self._normalize_field_name(prop_name)
        return any(keyword in normalized for keyword in [
            "response", "result", "output", "return", "format", "schema"
        ])

    def _check_schema_for_directives(
        self, server_name: str, tool_name: str, schema: Any, schema_path: str, target: TargetConfig
    ) -> Finding | None:
        """Recursively check a schema object for action-directive fields."""
        if not isinstance(schema, dict):
            return None

        # Check direct properties
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for field_name, field_schema in properties.items():
                finding = self._check_field_for_directives(
                    server_name, tool_name, field_name, field_schema, 
                    f"{schema_path}.properties.{field_name}", target
                )
                if finding:
                    return finding

        # Check array items
        items = schema.get("items", {})
        if isinstance(items, dict):
            finding = self._check_schema_for_directives(
                server_name, tool_name, items, f"{schema_path}.items", target
            )
            if finding:
                return finding

        # Check nested schemas (oneOf, allOf, anyOf)
        for nested_key in ["oneOf", "allOf", "anyOf"]:
            nested_schemas = schema.get(nested_key, [])
            if isinstance(nested_schemas, list):
                for i, nested_schema in enumerate(nested_schemas):
                    finding = self._check_schema_for_directives(
                        server_name, tool_name, nested_schema, 
                        f"{schema_path}.{nested_key}[{i}]", target
                    )
                    if finding:
                        return finding

        # Check additional properties
        additional_props = schema.get("additionalProperties")
        if isinstance(additional_props, dict):
            finding = self._check_schema_for_directives(
                server_name, tool_name, additional_props, 
                f"{schema_path}.additionalProperties", target
            )
            if finding:
                return finding

        return None

    def _check_field_for_directives(
        self, server_name: str, tool_name: str, field_name: str, 
        field_schema: Any, field_path: str, target: TargetConfig
    ) -> Finding | None:
        """Check a specific field for action-directive patterns."""
        # Normalize field name for pattern matching
        normalized_name = self._normalize_field_name(field_name)
        
        # Check for primary patterns (auto-flag)
        if normalized_name in self.PRIMARY_PATTERNS:
            return self._make_finding(
                server_name=server_name,
                tool_name=tool_name,
                field_name=field_name,
                field_path=field_path,
                pattern_type="primary",
                observable=f"Primary action-directive field '{field_name}' found in tool '{tool_name}' response schema",
                target=target,
            )

        # Check for secondary patterns with context analysis
        if normalized_name in self.SECONDARY_PATTERNS:
            if self._is_instructional_field(field_schema):
                return self._make_finding(
                    server_name=server_name,
                    tool_name=tool_name,
                    field_name=field_name,
                    field_path=field_path,
                    pattern_type="secondary",
                    observable=f"Secondary action-directive field '{field_name}' with instructional schema found in tool '{tool_name}'",
                    target=target,
                )

        # Check for equivalent naming patterns
        if self._is_equivalent_instruction_field(normalized_name):
            return self._make_finding(
                server_name=server_name,
                tool_name=tool_name,
                field_name=field_name,
                field_path=field_path,
                pattern_type="equivalent",
                observable=f"Semantically equivalent action-directive field '{field_name}' found in tool '{tool_name}' response schema",
                target=target,
            )

        # Check for instruction-structured schemas regardless of field name
        if self._has_instruction_structure(field_schema):
            return self._make_finding(
                server_name=server_name,
                tool_name=tool_name,
                field_name=field_name,
                field_path=field_path,
                pattern_type="structural",
                observable=f"Field '{field_name}' has instruction-structured schema in tool '{tool_name}' response",
                target=target,
            )

        # Recursively check nested schemas
        if isinstance(field_schema, dict):
            return self._check_schema_for_directives(
                server_name, tool_name, field_schema, field_path, target
            )

        return None

    def _normalize_field_name(self, field_name: str) -> str:
        """Normalize field name for pattern matching - handles case, Unicode, prefixes/suffixes."""
        # Unicode normalization to handle homoglyph attacks
        normalized = unicodedata.normalize('NFKD', field_name)
        # Convert to ASCII, removing accents
        normalized = normalized.encode('ascii', 'ignore').decode('ascii')
        # Convert to lowercase
        normalized = normalized.lower()
        # Remove common prefixes and suffixes
        normalized = re.sub(r'^[_\-]+', '', normalized)  # Leading underscores/hyphens
        normalized = re.sub(r'[_\-]+$', '', normalized)  # Trailing underscores/hyphens
        normalized = re.sub(r'_?(list|array|items|data|info)$', '', normalized)  # Common suffixes
        normalized = re.sub(r'^(get|fetch|retrieve)_?', '', normalized)  # Common prefixes
        # Convert camelCase to snake_case
        normalized = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', normalized).lower()
        return normalized

    def _is_instructional_field(self, field_schema: Any) -> bool:
        """Check if field schema indicates instructional content."""
        if not isinstance(field_schema, dict):
            return False

        # Check description for instructional keywords
        description = field_schema.get("description", "").lower()
        if any(keyword in description for keyword in self.INSTRUCTIONAL_KEYWORDS):
            return True

        # Check if it's an array of instruction-like objects
        if field_schema.get("type") == "array":
            items = field_schema.get("items", {})
            if isinstance(items, dict):
                return self._has_instruction_structure(items)

        # Check if it's an object with instruction-like structure
        return self._has_instruction_structure(field_schema)

    def _is_equivalent_instruction_field(self, normalized_name: str) -> bool:
        """Check for semantically equivalent instruction field names."""
        equivalent_patterns = {
            "action_plan", "step_sequence", "workflow_items", "procedure_steps",
            "execution_plan", "operation_plan", "command_sequence", "directive_sequence",
            "task_flow", "step_flow", "action_flow", "work_flow", "process_flow",
            "job_list", "activity_list", "operation_list", "procedure_list",
            "step_by_step", "how_to_proceed", "what_next", "do_next",
            "continuation", "follow_through", "next_phase", "subsequent_steps",
        }
        return normalized_name in equivalent_patterns

    def _has_instruction_structure(self, schema: Any) -> bool:
        """Check if schema has structure typical of tool call instructions."""
        if not isinstance(schema, dict):
            return False

        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return False

        # Look for tool call structure patterns
        tool_call_indicators = {"tool_name", "function", "method", "command", "action"}
        param_indicators = {"parameters", "params", "args", "arguments", "input", "data"}

        has_tool_indicator = any(
            self._normalize_field_name(prop) in tool_call_indicators 
            for prop in properties.keys()
        )
        has_param_indicator = any(
            self._normalize_field_name(prop) in param_indicators 
            for prop in properties.keys()
        )

        # If it looks like a tool call structure, it's likely instructional
        if has_tool_indicator and has_param_indicator:
            return True

        # Check for arrays that might contain instruction sequences
        if schema.get("type") == "array":
            items = schema.get("items", {})
            if isinstance(items, dict):
                return self._has_instruction_structure(items)

        return False

    def _make_finding(
        self,
        server_name: str,
        tool_name: str,
        field_name: str,
        field_path: str,
        pattern_type: str,
        observable: str,
        target: TargetConfig,
    ) -> Finding:
        """Create a finding for an action-directive field."""
        return Finding(
            check_id=self.check_id,
            severity=self.severity.default,
            confidence="high",
            evidence=Evidence(
                observable=observable,
                file_path=self._resolve_config_path(target),
                line=None,
                line_end=None,
                raw_value=f"{field_path}: action-directive field detected (pattern: {pattern_type})",
                context={
                    "mcp_server": server_name,
                    "tool_name": tool_name,
                    "field_name": field_name,
                    "field_path": field_path,
                    "pattern_type": pattern_type,
                },
            ),
            remediation=Remediation(
                description=(
                    "Remove action-directive fields from MCP tool response schemas and "
                    "ensure tools return data only, not instructions. If workflow "
                    "coordination is needed, implement it at the agent level, not in "
                    "tool response schemas."
                ),
                steps={
                    "mcp_generic": (
                        "1. Remove the action-directive field from the tool response schema\n"
                        "2. Ensure response schemas contain only data fields (result, data, status, timestamp)\n"
                        "3. If workflow coordination is needed, implement it in the agent's reasoning layer\n"
                        "4. Add response schema validation to strip any instruction-like fields"
                    ),
                    "openclaw": (
                        "1. Edit the skill definition file and remove action-directive fields from response schema\n"
                        "2. Update skill to return data-only responses\n"
                        "3. If multi-step workflows are needed, use OpenClaw's built-in task orchestration\n"
                        "4. Add schema validation in skill handler: response = {k: v for k, v in response.items() if k not in DIRECTIVE_FIELDS}"
                    ),
                    "langchain": (
                        "1. Update custom tool response schemas to remove action-directive fields\n"
                        "2. Add response filtering in AgentExecutor before LLM processing:\n"
                        "   def filter_response(response):\n"
                        "       return {k: v for k, v in response.items() if not is_directive_field(k)}\n"
                        "3. Use LangChain's chain composition for workflow orchestration instead"
                    ),
                    "crewai": (
                        "1. Remove action-directive fields from tool response schemas\n"
                        "2. Sanitize inter-agent task results before processing:\n"
                        "   result = {k: v for k, v in tool_result.items() if not is_instruction_field(k)}\n"
                        "3. Use CrewAI's task dependencies for workflow coordination\n"
                        "4. Ensure agent-to-agent communication uses structured task format, not instruction injection"
                    ),
                    "autogen": (
                        "1. Update function schemas to remove action-directive fields\n"
                        "2. Add response sanitization in function execution wrapper\n"
                        "3. Use AutoGen's conversation flow control for multi-step processes\n"
                        "4. Implement schema validation middleware: response = sanitize_response(tool_output)"
                    ),
                },
                references=[
                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/",
                ],
                effort="medium",
            ),
            taxonomy=self.taxonomy,
        )

    def _resolve_config_path(self, target: TargetConfig) -> str | None:
        """Resolve the config file path for this target."""
        framework_paths = {
            "openclaw": "~/.openclaw/config.json",
            "mcp_generic": "mcp-config.json",
            "langchain": "langchain-config.json", 
            "crewai": "crew-config.yaml",
            "autogen": "autogen-config.json",
        }
        return target.metadata.get("config_path", framework_paths.get(target.framework))