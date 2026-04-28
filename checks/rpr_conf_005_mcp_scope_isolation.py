"""
RPR-CONF-005: MCP Scope Boundary and Isolation Failures

Detects cross-boundary security failures between MCP servers including tool name collisions,
shared credential stores, missing network egress restrictions, and inadequate URL allowlists.
These configuration gaps enable identity confusion attacks and covert data exfiltration channels.
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


class RprConf005McpScopeIsolation(ReaperCheck):
    """Detect MCP scope boundary and isolation failures."""

    # --- Identity (Contract §2) ---
    check_id = "RPR-CONF-005"
    name = "MCP Scope Boundary and Isolation Failures"
    description = (
        "Detects cross-boundary security failures between MCP servers including "
        "tool name collisions, shared credential stores, missing network egress "
        "restrictions, and inadequate URL allowlists. These configuration gaps "
        "enable identity confusion attacks and covert data exfiltration channels."
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
            entry_id="ASI07",
            justification=(
                "This check directly addresses ASI07 (Insecure Plugin Design) by "
                "detecting cross-boundary isolation failures between MCP servers "
                "that enable privilege escalation and data exfiltration through "
                "namespace confusion and inadequate egress controls."
            ),
        ),
        secondary=[
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-668",
                justification=(
                    "Maps to CWE-668 (Exposure of Resource to Wrong Sphere) as the "
                    "vulnerability involves MCP servers accessing resources outside "
                    "their intended scope due to inadequate boundary controls."
                ),
            ),
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-284",
                justification=(
                    "Maps to CWE-284 (Improper Access Control) as the vulnerability "
                    "stems from insufficient access controls between MCP server "
                    "boundaries and network egress points."
                ),
            ),
        ],
    )

    # --- Severity (Contract §5) ---
    severity = SeverityRating(
        default="high",
        cvss_base=7.0,
        aarf=None,
    )

    # --- Detection Logic (Contract §6) ---

    # Risky file path patterns
    RISKY_FILE_PATHS = {
        "dropbox", "google_drive", "gdrive", "onedrive", "s3_mount",
        "synced", "cloud", "backup", "shared", "external"
    }

    # Network egress policy indicators
    NETWORK_EGRESS_POLICIES = {
        "egress_policy", "network_policy", "allowed_hosts", "blocked_hosts",
        "network_restrictions", "outbound_rules", "firewall_rules"
    }

    # URL allowlist field names
    URL_ALLOWLIST_FIELDS = {
        "allowed_domains", "url_allowlist", "allowed_urls", "domain_allowlist",
        "whitelist_domains", "permitted_domains", "allowed_hosts"
    }

    def detect(self, target: TargetConfig) -> Finding | None:
        """Check for MCP scope boundary and isolation failures."""
        
        # If no MCP servers, no cross-boundary issues possible
        if not target.mcp_servers or len(target.mcp_servers) < 1:
            return None

        # Check for tool name collisions (D4-01)
        collision_finding = self._check_tool_name_collisions(target)
        if collision_finding:
            return collision_finding

        # Check for shared credential stores (D4-09)
        shared_creds_finding = self._check_shared_credentials(target)
        if shared_creds_finding:
            return shared_creds_finding

        # Check for missing URL allowlists on HTTP tools (D4-07)
        http_allowlist_finding = self._check_http_allowlists(target)
        if http_allowlist_finding:
            return http_allowlist_finding

        # Check for missing network egress restrictions (D4-10)
        egress_finding = self._check_network_egress_restrictions(target)
        if egress_finding:
            return egress_finding

        # Check for risky file paths (D4-05)
        file_path_finding = self._check_risky_file_paths(target)
        if file_path_finding:
            return file_path_finding

        # Check for external log shipping without PII filtering (D4-06)
        log_shipping_finding = self._check_external_log_shipping(target)
        if log_shipping_finding:
            return log_shipping_finding

        return None

    def _check_tool_name_collisions(self, target: TargetConfig) -> Finding | None:
        """Check for tool name collisions across MCP servers."""
        tool_names = {}  # tool_name -> list of server_names
        
        # Collect tool names from all MCP servers
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            server_tools = server.get("tools", [])
            
            for tool in server_tools:
                tool_name = tool.get("name", "")
                if tool_name:
                    if tool_name not in tool_names:
                        tool_names[tool_name] = []
                    tool_names[tool_name].append(server_name)

        # Also check tools declared at the top level
        for tool in target.tools:
            tool_name = tool.get("name", "")
            if tool_name:
                if tool_name not in tool_names:
                    tool_names[tool_name] = []
                tool_names[tool_name].append("global")

        # Find collisions
        for tool_name, servers in tool_names.items():
            if len(servers) > 1:
                # Exact collision - critical if no qualified naming
                return self._make_finding(
                    observable=f"Tool name '{tool_name}' collides across MCP servers: {', '.join(servers)}",
                    raw_value=f"tool_name: '{tool_name}' found in servers: {servers}",
                    context={
                        "collision_type": "exact",
                        "tool_name": tool_name,
                        "affected_servers": ", ".join(servers),
                        "collision_count": str(len(servers))
                    },
                    file_path=self._resolve_config_path(target),
                    severity="critical"  # Identity confusion enables privilege escalation
                )

        return None

    def _check_shared_credentials(self, target: TargetConfig) -> Finding | None:
        """Check for shared credential stores across servers."""
        credential_stores = {}  # credential_ref -> list of server_names
        
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            auth = server.get("auth", {})
            
            # Check for credential store references
            cred_ref = None
            if "credential_store" in auth:
                cred_ref = auth["credential_store"]
            elif "vault_path" in auth:
                cred_ref = auth["vault_path"]
            elif "keyring" in auth:
                cred_ref = auth["keyring"]
            elif "credential_id" in auth:
                cred_ref = auth["credential_id"]
            
            if cred_ref:
                if cred_ref not in credential_stores:
                    credential_stores[cred_ref] = []
                credential_stores[cred_ref].append(server_name)

        # Find shared credential stores
        for cred_ref, servers in credential_stores.items():
            if len(servers) > 1:
                return self._make_finding(
                    observable=f"Credential store '{cred_ref}' shared across MCP servers: {', '.join(servers)}",
                    raw_value=f"credential_store: '{cred_ref}' used by servers: {servers}",
                    context={
                        "shared_credential_group": cred_ref,
                        "blast_radius": ", ".join(servers),
                        "affected_server_count": str(len(servers))
                    },
                    file_path=self._resolve_config_path(target),
                    severity="medium"
                )

        return None

    def _check_http_allowlists(self, target: TargetConfig) -> Finding | None:
        """Check for HTTP/webhook tools without URL allowlists."""
        # Check tools in all MCP servers
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            server_tools = server.get("tools", [])
            
            for tool in server_tools:
                if self._is_http_tool(tool):
                    if not self._has_url_allowlist(tool):
                        tool_name = tool.get("name", "<unnamed>")
                        return self._make_finding(
                            observable=f"HTTP tool '{tool_name}' in server '{server_name}' lacks URL allowlist",
                            raw_value=f"servers.{server_name}.tools.{tool_name}: no URL allowlist configured",
                            context={
                                "tool_name": tool_name,
                                "server_name": server_name,
                                "tool_type": "http"
                            },
                            file_path=self._resolve_config_path(target),
                            severity="critical"  # Unrestricted HTTP = covert channel
                        )

        # Check global tools
        for tool in target.tools:
            if self._is_http_tool(tool):
                if not self._has_url_allowlist(tool):
                    tool_name = tool.get("name", "<unnamed>")
                    return self._make_finding(
                        observable=f"Global HTTP tool '{tool_name}' lacks URL allowlist",
                        raw_value=f"tools.{tool_name}: no URL allowlist configured",
                        context={
                            "tool_name": tool_name,
                            "server_name": "global",
                            "tool_type": "http"
                        },
                        file_path=self._resolve_config_path(target),
                        severity="critical"
                    )

        return None

    def _check_network_egress_restrictions(self, target: TargetConfig) -> Finding | None:
        """Check for missing network egress restrictions."""
        unrestricted_servers = []
        
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            
            # Check if server has any network egress policy
            has_egress_policy = False
            for policy_field in self.NETWORK_EGRESS_POLICIES:
                if policy_field in server:
                    has_egress_policy = True
                    break
            
            if not has_egress_policy:
                unrestricted_servers.append(server_name)

        if unrestricted_servers:
            return self._make_finding(
                observable=f"MCP servers lack network egress restrictions: {', '.join(unrestricted_servers)}",
                raw_value=f"servers without egress_policy: {unrestricted_servers}",
                context={
                    "unrestricted_servers": ", ".join(unrestricted_servers),
                    "unrestricted_count": str(len(unrestricted_servers)),
                    "risk_level": "critical"
                },
                file_path=self._resolve_config_path(target),
                severity="critical"  # D4-10: Unrestricted egress = every write tool becomes exfil sink
            )

        return None

    def _check_risky_file_paths(self, target: TargetConfig) -> Finding | None:
        """Check for file write paths pointing to synced directories."""
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            server_tools = server.get("tools", [])
            
            for tool in server_tools:
                if self._is_file_write_tool(tool):
                    file_paths = self._extract_file_paths(tool)
                    for file_path in file_paths:
                        if self._is_risky_file_path(file_path):
                            tool_name = tool.get("name", "<unnamed>")
                            return self._make_finding(
                                observable=f"File tool '{tool_name}' in server '{server_name}' writes to risky path: {file_path}",
                                raw_value=f"servers.{server_name}.tools.{tool_name}.path: '{file_path}'",
                                context={
                                    "tool_name": tool_name,
                                    "server_name": server_name,
                                    "risky_path": file_path,
                                    "covert_channel": "X3-C"
                                },
                                file_path=self._resolve_config_path(target),
                                severity="high"
                            )

        return None

    def _check_external_log_shipping(self, target: TargetConfig) -> Finding | None:
        """Check for external log shipping without PII filtering."""
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            logging_config = server.get("logging", {})
            
            # Check for external log destinations
            external_loggers = logging_config.get("external", [])
            if not isinstance(external_loggers, list):
                external_loggers = [external_loggers] if external_loggers else []
                
            for logger in external_loggers:
                if isinstance(logger, dict):
                    destination = logger.get("destination", "")
                    pii_filter = logger.get("pii_filter", False)
                    
                    if destination and not pii_filter:
                        return self._make_finding(
                            observable=f"MCP server '{server_name}' ships logs to external destination without PII filtering: {destination}",
                            raw_value=f"servers.{server_name}.logging.external: destination='{destination}', pii_filter=false",
                            context={
                                "server_name": server_name,
                                "log_destination": destination,
                                "pii_filter": "disabled",
                                "covert_channel": "X3-D"
                            },
                            file_path=self._resolve_config_path(target),
                            severity="medium"
                        )

        return None

    def _is_http_tool(self, tool: dict) -> bool:
        """Check if tool is HTTP/webhook capable."""
        tool_type = tool.get("type", "").lower()
        tool_name = tool.get("name", "").lower()
        
        http_indicators = {
            "http", "webhook", "api", "rest", "fetch", "request", "curl", "web"
        }
        
        return (tool_type in http_indicators or 
                any(indicator in tool_name for indicator in http_indicators) or
                "url" in tool.get("inputSchema", {}).get("properties", {}))

    def _has_url_allowlist(self, tool: dict) -> bool:
        """Check if tool has URL allowlist configured."""
        config = tool.get("config", {})
        
        # Check for any allowlist field
        for field in self.URL_ALLOWLIST_FIELDS:
            allowlist = config.get(field)
            if allowlist:
                # Must have actual restrictions, not wildcard
                if isinstance(allowlist, list) and allowlist and "*" not in str(allowlist):
                    return True
                elif isinstance(allowlist, str) and allowlist.strip() and "*" not in allowlist:
                    return True
        
        return False

    def _is_file_write_tool(self, tool: dict) -> bool:
        """Check if tool can write files."""
        tool_type = tool.get("type", "").lower()
        tool_name = tool.get("name", "").lower()
        
        write_indicators = {
            "file", "write", "save", "create", "store", "upload", "put"
        }
        
        return (tool_type in write_indicators or
                any(indicator in tool_name for indicator in write_indicators))

    def _extract_file_paths(self, tool: dict) -> list[str]:
        """Extract file paths from tool configuration."""
        paths = []
        config = tool.get("config", {})
        
        # Common path fields
        path_fields = ["path", "directory", "base_path", "root_dir", "output_dir"]
        for field in path_fields:
            path = config.get(field)
            if isinstance(path, str) and path.strip():
                paths.append(path.strip())
            elif isinstance(path, list):
                paths.extend([p for p in path if isinstance(p, str) and p.strip()])
        
        return paths

    def _is_risky_file_path(self, file_path: str) -> bool:
        """Check if file path points to a synced/cloud directory."""
        path_lower = file_path.lower()
        return any(risky_pattern in path_lower for risky_pattern in self.RISKY_FILE_PATHS)

    def _make_finding(
        self,
        observable: str,
        raw_value: str,
        context: dict[str, str],
        file_path: str | None,
        severity: str | None = None,
    ) -> Finding:
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
                context=context,
            ),
            remediation=Remediation(
                description=(
                    "Implement namespace isolation, credential separation, network "
                    "egress restrictions, and per-channel controls to close "
                    "cross-boundary gaps. Add strict URL allowlists to all HTTP tools "
                    "and implement network-level egress restrictions on MCP server processes."
                ),
                steps={
                    "universal": (
                        "1. Ensure unique tool names across all MCP servers using "
                        "server-qualified naming (server.tool_name).\n"
                        "2. Separate credential stores per MCP server to prevent "
                        "cross-server credential leakage.\n"
                        "3. Add strict URL allowlists to ALL HTTP/webhook tools: "
                        'allowed_domains: ["trusted-api.com", "internal.corp"]\n'
                        "4. Implement network egress restrictions on MCP server processes: "
                        "egress_policy: { allowed_hosts: [...], blocked_hosts: [...] }\n"
                        "5. Restrict file write paths to non-synced directories.\n"
                        "6. Enable PII filtering on external log shipping: "
                        "pii_filter: true"
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
        """Resolve the config file path for this framework."""
        if target.framework == "openclaw":
            return target.metadata.get("config_path", "~/.openclaw/config.json")
        elif target.framework == "langchain":
            return target.metadata.get("config_path", "./langchain_config.json")
        elif target.framework == "crewai":
            return target.metadata.get("config_path", "./crew_config.yaml")
        return target.metadata.get("config_path", "./mcp_config.json")