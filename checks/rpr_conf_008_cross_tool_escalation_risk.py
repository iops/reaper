"""
RPR-CONF-008: Cross-tool privilege escalation risk patterns

Detects tool combinations that enable privilege escalation through cross-tool
capability chaining. Identifies high-risk patterns where tools with different
privilege levels lack proper isolation and can be combined to exceed individual
tool permissions.
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


class RprConf008CrossToolEscalation(ReaperCheck):
    """Detect cross-tool privilege escalation risk patterns."""

    # --- Identity (Contract §2) ---
    check_id = "RPR-CONF-008"
    name = "Cross-tool privilege escalation risk patterns"
    description = (
        "Detects tool combinations that enable privilege escalation through cross-tool "
        "capability chaining. Identifies high-risk patterns where tools with different "
        "privilege levels (read/write, credential access, filesystem) lack proper "
        "isolation and can be combined to exceed individual tool permissions."
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
                "This check detects tool isolation failures that enable privilege "
                "escalation, directly mapping to ASI03's scope of tool security and "
                "permission boundaries"
            ),
        ),
        secondary=[
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-269",
                justification=(
                    "Improper privilege management through tool combination allowing "
                    "elevation beyond intended permissions"
                ),
            ),
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-862",
                justification=(
                    "Missing authorization checks between tools that should be isolated"
                ),
            ),
        ],
    )

    # --- Severity (Contract §5) ---
    severity = SeverityRating(
        default="high",
        cvss_base=7.8,
        aarf=None,
    )

    # --- Detection Logic (Contract §6) ---

    # High-risk capability combinations for E1 credential harvesting
    CREDENTIAL_READ_CAPABILITIES = {
        "file_read", "filesystem_read", "env_read", "config_read", 
        "database_read", "vault_read", "secret_read"
    }
    
    CREDENTIAL_USE_CAPABILITIES = {
        "api_call", "http_request", "webhook", "email_send", 
        "database_write", "cloud_api", "auth_request"
    }

    # High-risk capability combinations for E4 read-to-write elevation
    READ_CAPABILITIES = {
        "file_read", "database_read", "api_read", "config_read",
        "log_read", "system_read", "user_read"
    }
    
    WRITE_CAPABILITIES = {
        "file_write", "database_write", "api_write", "email_send",
        "webhook", "system_write", "config_write", "cloud_upload"
    }

    def detect(self, target: TargetConfig) -> Finding | None:
        """Check for dangerous tool capability combinations and MCP isolation issues."""
        
        # Check for E5: MCP servers with shared state leakage
        mcp_finding = self._check_mcp_isolation(target)
        if mcp_finding:
            return mcp_finding

        # Check for E1: Credential harvesting patterns
        credential_finding = self._check_credential_escalation(target)
        if credential_finding:
            return credential_finding

        # Check for E4: Read-to-write elevation patterns
        read_write_finding = self._check_read_write_elevation(target)
        if read_write_finding:
            return read_write_finding

        return None

    def _check_mcp_isolation(self, target: TargetConfig) -> Finding | None:
        """Check for MCP servers without proper process isolation."""
        if len(target.mcp_servers) < 2:
            return None

        shared_process_servers = []
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            
            # Check for explicit shared_process=true
            if server.get("shared_process") is True:
                shared_process_servers.append(server_name)
                continue
                
            # Check for missing isolation configuration
            isolation_config = server.get("isolation", {})
            if not isolation_config:
                shared_process_servers.append(server_name)
                continue
                
            # Check for disabled process separation
            separate_process = isolation_config.get("separate_process")
            if separate_process is False:
                shared_process_servers.append(server_name)

        if len(shared_process_servers) >= 2:
            return self._make_finding(
                pattern="E5 - Shared state leakage",
                observable=f"Multiple MCP servers without process isolation: {', '.join(shared_process_servers)}",
                raw_value=f"MCP servers sharing process: {shared_process_servers}",
                context={
                    "escalation_type": "shared_state_leakage",
                    "affected_servers": shared_process_servers,
                    "server_count": str(len(shared_process_servers))
                }
            )

        return None

    def _check_credential_escalation(self, target: TargetConfig) -> Finding | None:
        """Check for credential harvesting tool combinations."""
        cred_read_tools = []
        cred_use_tools = []

        for tool in target.tools:
            tool_name = tool.get("name", "<unnamed>")
            capabilities = self._extract_capabilities(tool)
            
            if any(cap in self.CREDENTIAL_READ_CAPABILITIES for cap in capabilities):
                cred_read_tools.append(tool_name)
                
            if any(cap in self.CREDENTIAL_USE_CAPABILITIES for cap in capabilities):
                cred_use_tools.append(tool_name)

        if cred_read_tools and cred_use_tools:
            return self._make_finding(
                pattern="E1 - Credential harvesting",
                observable=f"Tools enable credential harvesting: read from {cred_read_tools}, use via {cred_use_tools}",
                raw_value=f"credential_read_tools: {cred_read_tools}, credential_use_tools: {cred_use_tools}",
                context={
                    "escalation_type": "credential_harvesting",
                    "read_tools": cred_read_tools,
                    "use_tools": cred_use_tools
                }
            )

        return None

    def _check_read_write_elevation(self, target: TargetConfig) -> Finding | None:
        """Check for read-to-write privilege elevation patterns."""
        read_tools = []
        write_tools = []

        for tool in target.tools:
            tool_name = tool.get("name", "<unnamed>")
            capabilities = self._extract_capabilities(tool)
            
            # Only flag as read tool if it has read capabilities but NO write capabilities
            has_read = any(cap in self.READ_CAPABILITIES for cap in capabilities)
            has_write = any(cap in self.WRITE_CAPABILITIES for cap in capabilities)
            
            if has_read and not has_write:
                read_tools.append(tool_name)
            elif has_write:
                write_tools.append(tool_name)

        if read_tools and write_tools:
            return self._make_finding(
                pattern="E4 - Read-to-write elevation",
                observable=f"Tools enable read-to-write elevation: read-only {read_tools}, write-capable {write_tools}",
                raw_value=f"read_only_tools: {read_tools}, write_tools: {write_tools}",
                context={
                    "escalation_type": "read_write_elevation",
                    "read_only_tools": read_tools,
                    "write_tools": write_tools
                }
            )

        return None

    def _extract_capabilities(self, tool: dict) -> set[str]:
        """Extract capability indicators from tool configuration."""
        capabilities = set()
        
        # Check explicit capabilities field
        if "capabilities" in tool:
            caps = tool["capabilities"]
            if isinstance(caps, list):
                capabilities.update(caps)
            elif isinstance(caps, str):
                capabilities.add(caps)
        
        # Infer capabilities from tool name and description
        tool_name = tool.get("name", "").lower()
        tool_desc = tool.get("description", "").lower()
        combined_text = f"{tool_name} {tool_desc}"
        
        # File/filesystem indicators
        if any(term in combined_text for term in ["file", "filesystem", "fs", "read_file", "write_file"]):
            if any(term in combined_text for term in ["read", "get", "fetch", "load"]):
                capabilities.add("file_read")
            if any(term in combined_text for term in ["write", "save", "create", "update"]):
                capabilities.add("file_write")
        
        # Database indicators
        if any(term in combined_text for term in ["database", "db", "sql", "query"]):
            if any(term in combined_text for term in ["read", "select", "get", "fetch"]):
                capabilities.add("database_read")
            if any(term in combined_text for term in ["write", "insert", "update", "delete"]):
                capabilities.add("database_write")
        
        # API/HTTP indicators
        if any(term in combined_text for term in ["api", "http", "request", "rest", "webhook"]):
            if any(term in combined_text for term in ["get", "fetch", "read"]):
                capabilities.add("api_read")
            if any(term in combined_text for term in ["post", "put", "send", "call"]):
                capabilities.add("api_call")
        
        # Email indicators
        if any(term in combined_text for term in ["email", "mail", "smtp", "send"]):
            capabilities.add("email_send")
        
        # Environment/config indicators
        if any(term in combined_text for term in ["env", "environment", "config", "settings"]):
            if any(term in combined_text for term in ["read", "get"]):
                capabilities.add("env_read")
        
        # Check tool schema for method indicators
        input_schema = tool.get("inputSchema", {})
        if isinstance(input_schema, dict):
            properties = input_schema.get("properties", {})
            for prop_name in properties:
                if "path" in prop_name.lower() or "file" in prop_name.lower():
                    capabilities.add("file_read")
                if "url" in prop_name.lower() or "endpoint" in prop_name.lower():
                    capabilities.add("api_call")
        
        return capabilities

    def _make_finding(
        self,
        pattern: str,
        observable: str,
        raw_value: str,
        context: dict[str, str | list[str]],
    ) -> Finding:
        """Create a finding for cross-tool escalation risk."""
        return Finding(
            check_id=self.check_id,
            severity=self.severity.default,
            confidence="high",
            evidence=Evidence(
                observable=observable,
                file_path=self._resolve_config_path(),
                line=None,
                line_end=None,
                raw_value=raw_value,
                context=context,
            ),
            remediation=Remediation(
                description=(
                    "Implement tool isolation with separate processes/containers and add "
                    "cross-tool data flow monitoring. Prevent tools from combining "
                    "capabilities that exceed individual tool permissions."
                ),
                steps={
                    "universal": (
                        "1. ISOLATE MCP SERVERS: Run each MCP server in separate processes/containers:\n"
                        '   isolation: { separate_process: true, shared_env: false }\n\n'
                        "2. IMPLEMENT DATA FLOW MONITORING: Track sensitive data movement between tools:\n"
                        '   - Tag data read from credential/sensitive sources\n'
                        '   - Require HITL approval when tagged data flows to write tools\n\n'
                        "3. RESTRICT TOOL COMBINATIONS: Use tool isolation boundaries:\n"
                        '   - Group tools by privilege level (read-only, write, credential-access)\n'
                        '   - Prevent cross-group data flow without explicit approval\n\n'
                        "4. CREDENTIAL ISOLATION: Each tool gets separate credential scope:\n"
                        '   - No shared environment variables between tools\n'
                        '   - Tool-specific credential stores\n'
                        '   - No shared temporary directories'
                    ),
                    "openclaw": (
                        "Deploy MCP servers as separate Docker containers:\n"
                        '  servers:\n'
                        '    server1:\n'
                        '      command: ["docker", "run", "--rm", "server1-image"]\n'
                        '      isolation: { separate_process: true }\n'
                        '    server2:\n'
                        '      command: ["docker", "run", "--rm", "server2-image"]\n'
                        '      isolation: { separate_process: true }\n'
                        'Use OpenClaw\'s secret manager with per-server scoping.'
                    ),
                    "langchain": (
                        "Use separate tool executor contexts:\n"
                        '  from langchain.agents import ToolPermissionGuard\n'
                        '  guard = ToolPermissionGuard()\n'
                        '  guard.add_isolation_rule("file_read", "api_call", require_approval=True)\n'
                        'Implement data provenance tracking across tool calls.'
                    ),
                    "crewai": (
                        "Set allow_delegation: false and isolate crew contexts:\n"
                        '  crew = Crew(\n'
                        '      agents=[agent1, agent2],\n'
                        '      allow_delegation=False,\n'
                        '      process=Process.hierarchical\n'
                        '  )\n'
                        'Use supervisory agent to approve cross-agent data flows.'
                    ),
                },
                references=[
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                ],
                effort="high",
            ),
            taxonomy=self.taxonomy,
        )

    def _resolve_config_path(self) -> str | None:
        """Resolve the configuration file path."""
        return "agent_config"