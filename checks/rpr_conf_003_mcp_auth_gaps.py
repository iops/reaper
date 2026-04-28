"""
RPR-CONF-003: MCP Server Authentication and Authorization Configuration Gaps

Detects authentication and authorization configuration gaps in MCP server declarations 
that undermine security controls. Identifies missing authentication requirements, 
inadequate authorization granularity, excessive OAuth scopes, insecure credential 
storage, and shared credentials across servers.
"""

from __future__ import annotations

import re
from typing import Dict, List

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


class RprConf003McpAuthGaps(ReaperCheck):
    """Detect MCP server authentication and authorization configuration gaps."""

    # --- Identity (Contract §2) ---
    check_id = "RPR-CONF-003"
    name = "MCP Server Authentication and Authorization Configuration Gaps"
    description = (
        "Detects authentication and authorization configuration gaps in MCP server "
        "declarations that undermine security controls. Identifies missing authentication "
        "requirements, inadequate authorization granularity, excessive OAuth scopes, "
        "insecure credential storage, and shared credentials across servers."
    )
    contract_version = "1.0"

    # --- Classification (Contract §3) ---
    category = "config"
    wedge = 1
    tier = "community"
    frameworks = ["openclaw", "langchain", "crewai", "mcp_generic"]
    check_type = "deterministic"

    # --- Taxonomy (Contract §4) ---
    taxonomy = TaxonomyMapping(
        primary=TaxonomyEntry(
            framework="owasp_asi",
            entry_id="ASI03",
            justification=(
                "This check directly addresses ASI03 (Supply Chain and Plugin Vulnerabilities) "
                "by identifying authentication and authorization gaps in MCP server configurations "
                "that can lead to unauthorized access to external services and tools."
            ),
        ),
        secondary=[
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-287",
                justification=(
                    "Improper Authentication - detecting missing or inadequate authentication "
                    "mechanisms in MCP server configurations"
                ),
            ),
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-862",
                justification=(
                    "Missing Authorization - identifying insufficient authorization controls "
                    "and granularity in MCP server access"
                ),
            ),
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-522",
                justification=(
                    "Insufficiently Protected Credentials - detecting plaintext credential "
                    "storage in configuration files"
                ),
            ),
        ],
    )

    # --- Severity (Contract §5) ---
    severity = SeverityRating(
        default="critical",
        cvss_base=9.1,
        aarf=None,
    )

    # --- Detection Logic (Contract §6) ---

    CREDENTIAL_PATTERNS = [
        r"sk-[a-zA-Z0-9]{32,}",  # OpenAI API keys
        r"api_key[\"']\s*:\s*[\"'][a-zA-Z0-9+/]{16,}[\"']",  # Generic API keys
        r"bearer\s+[a-zA-Z0-9+/]{16,}",  # Bearer tokens
        r"postgres://[^@]+:[^@]+@",  # PostgreSQL connection strings
        r"mysql://[^@]+:[^@]+@",  # MySQL connection strings
        r"mongodb://[^@]+:[^@]+@",  # MongoDB connection strings
        r"access_token[\"']\s*:\s*[\"'][a-zA-Z0-9+/._-]{16,}[\"']",  # Access tokens
    ]

    EXCESSIVE_OAUTH_SCOPES = {
        "https://www.googleapis.com/auth/cloud-platform": ["storage", "compute"],
        "https://graph.microsoft.com/.default": ["mail", "files"],
        "admin": ["read", "write"],
        "full_access": ["read", "write", "delete"],
    }

    def detect(self, target: TargetConfig) -> Finding | None:
        """Check MCP server configurations for authentication and authorization gaps."""
        
        if not target.mcp_servers:
            return None

        # Check for missing authentication (highest priority)
        missing_auth = self._check_missing_authentication(target.mcp_servers)
        if missing_auth:
            return missing_auth

        # Check for inadequate authorization granularity
        granularity_issue = self._check_authorization_granularity(target.mcp_servers, target.tools)
        if granularity_issue:
            return granularity_issue

        # Check for excessive OAuth scopes
        scope_issue = self._check_oauth_scopes(target.mcp_servers)
        if scope_issue:
            return scope_issue

        # Check for insecure credential storage
        credential_issue = self._check_credential_storage(target)
        if credential_issue:
            return credential_issue

        # Check for shared credentials across servers
        shared_creds = self._check_shared_credentials(target.mcp_servers)
        if shared_creds:
            return shared_creds

        return None

    def _check_missing_authentication(self, mcp_servers: List[Dict]) -> Finding | None:
        """Check for MCP servers with no authentication configured."""
        for server in mcp_servers:
            server_name = server.get("name", "<unnamed>")
            auth = server.get("auth")

            if auth is None:
                return self._make_finding(
                    severity="critical",
                    observable=f"MCP server '{server_name}' has no authentication configuration",
                    raw_value=f"servers.{server_name}: no 'auth' key present",
                    context={"server_name": server_name, "issue_type": "missing_auth"},
                    file_path="mcp_config.json",
                )

            if isinstance(auth, dict) and auth.get("type") == "none":
                return self._make_finding(
                    severity="critical", 
                    observable=f"MCP server '{server_name}' explicitly disables authentication",
                    raw_value=f'servers.{server_name}.auth.type: "none"',
                    context={"server_name": server_name, "issue_type": "disabled_auth"},
                    file_path="mcp_config.json",
                )

        return None

    def _check_authorization_granularity(self, mcp_servers: List[Dict], tools: List[Dict]) -> Finding | None:
        """Check for inadequate authorization granularity."""
        for server in mcp_servers:
            server_name = server.get("name", "<unnamed>")
            auth = server.get("auth")

            if not auth or not isinstance(auth, dict):
                continue

            # Count tools served by this server
            server_tools = [tool for tool in tools if tool.get("server") == server_name]
            tool_count = len(server_tools)

            # If server has multiple tools but only server-level auth, that's inadequate
            if tool_count > 1 and not self._has_per_tool_auth(auth):
                return self._make_finding(
                    severity="high",
                    observable=f"MCP server '{server_name}' uses server-level auth for {tool_count} tools",
                    raw_value=f"servers.{server_name}.auth: server-level only, {tool_count} tools at risk",
                    context={
                        "server_name": server_name, 
                        "issue_type": "inadequate_granularity",
                        "tool_count_at_risk": str(tool_count),
                    },
                    file_path="mcp_config.json",
                )

        return None

    def _check_oauth_scopes(self, mcp_servers: List[Dict]) -> Finding | None:
        """Check for excessive OAuth scopes."""
        for server in mcp_servers:
            server_name = server.get("name", "<unnamed>")
            auth = server.get("auth", {})

            if auth.get("type") == "oauth" or auth.get("oauth"):
                oauth_config = auth.get("oauth", auth)
                scopes = oauth_config.get("scopes", [])

                for scope in scopes:
                    if scope in self.EXCESSIVE_OAUTH_SCOPES:
                        minimal_scopes = self.EXCESSIVE_OAUTH_SCOPES[scope]
                        return self._make_finding(
                            severity="medium",
                            observable=f"MCP server '{server_name}' requests excessive OAuth scope '{scope}'",
                            raw_value=f"servers.{server_name}.auth.oauth.scopes: [{scope}]",
                            context={
                                "server_name": server_name,
                                "issue_type": "excessive_oauth_scope",
                                "declared_scope": scope,
                                "recommended_scopes": ",".join(minimal_scopes),
                            },
                            file_path="mcp_config.json",
                        )

        return None

    def _check_credential_storage(self, target: TargetConfig) -> Finding | None:
        """Check for insecure credential storage patterns."""
        # Check config fields for plaintext credentials
        config_str = str(target.config)
        for pattern in self.CREDENTIAL_PATTERNS:
            if re.search(pattern, config_str, re.IGNORECASE):
                return self._make_finding(
                    severity="high",
                    observable="Plaintext credentials found in configuration",
                    raw_value="config contains credential patterns",
                    context={"issue_type": "plaintext_credentials", "location": "config"},
                    file_path="config.json",
                )

        # Check files for plaintext credentials
        for file_path, content in target.files.items():
            for pattern in self.CREDENTIAL_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    return self._make_finding(
                        severity="high", 
                        observable=f"Plaintext credentials found in file {file_path}",
                        raw_value=f"file {file_path} contains credential patterns",
                        context={"issue_type": "plaintext_credentials", "location": "files"},
                        file_path=file_path,
                    )

        return None

    def _check_shared_credentials(self, mcp_servers: List[Dict]) -> Finding | None:
        """Check for shared credentials across multiple servers."""
        credential_refs: Dict[str, List[str]] = {}

        for server in mcp_servers:
            server_name = server.get("name", "<unnamed>")
            auth = server.get("auth", {})

            # Extract credential references
            cred_ref = None
            if auth.get("token"):
                cred_ref = auth.get("token")
            elif auth.get("api_key"):
                cred_ref = auth.get("api_key") 
            elif auth.get("oauth", {}).get("client_id"):
                cred_ref = auth.get("oauth", {}).get("client_id")

            if cred_ref:
                if cred_ref not in credential_refs:
                    credential_refs[cred_ref] = []
                credential_refs[cred_ref].append(server_name)

        # Find shared credentials
        for cred_ref, servers in credential_refs.items():
            if len(servers) > 1:
                return self._make_finding(
                    severity="medium",
                    observable=f"Credential shared across {len(servers)} MCP servers: {', '.join(servers)}",
                    raw_value=f"credential_ref: {cred_ref[:20]}...",
                    context={
                        "issue_type": "shared_credentials",
                        "server_count": str(len(servers)),
                        "shared_servers": ",".join(servers),
                    },
                    file_path="mcp_config.json",
                )

        return None

    def _has_per_tool_auth(self, auth: Dict) -> bool:
        """Check if auth configuration supports per-tool authorization."""
        # Look for per-tool or per-operation auth structures
        return bool(
            auth.get("per_tool") or 
            auth.get("per_operation") or
            auth.get("tool_permissions") or
            auth.get("operation_permissions")
        )

    def _make_finding(
        self,
        severity: str,
        observable: str,
        raw_value: str,
        context: Dict[str, str],
        file_path: str | None,
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=severity,
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
                    "Implement authentication on all MCP servers with per-tool authorization, "
                    "minimal OAuth scopes, secure credential storage, and isolated credentials per server."
                ),
                steps={
                    "openclaw": (
                        'Configure MCP server authentication:\n'
                        '1. Add auth to each server in ~/.openclaw/config.json:\n'
                        '   "auth": {\n'
                        '     "type": "bearer",\n'
                        '     "token": "$MCP_SERVER_TOKEN",\n'
                        '     "per_tool": true\n'
                        '   }\n'
                        '2. Use separate tokens per server\n'
                        '3. Store tokens in environment variables\n'
                        '4. Reduce OAuth scopes to minimum required'
                    ),
                    "langchain": (
                        'Configure MCP server auth in your LangChain setup:\n'
                        '1. Add authentication middleware to MCP servers\n'
                        '2. Use separate API keys per tool integration\n'
                        '3. Store credentials in secret manager\n'
                        '4. Implement per-tool authorization checks'
                    ),
                    "crewai": (
                        'Configure per-agent credential contexts:\n'
                        '1. Remove shared service accounts across crew tools\n'
                        '2. Add per-tool auth configuration\n'
                        '3. Use minimal OAuth scopes per tool\n'
                        '4. Store credentials securely outside config files'
                    ),
                    "mcp_generic": (
                        'Implement MCP server authentication:\n'
                        '1. Add authentication to all MCP server endpoints\n'
                        '2. Use per-tool or per-operation authorization\n'
                        '3. Store credentials via secret manager with runtime injection\n'
                        '4. Set token expiration ≤24h with refresh mechanism\n'
                        '5. Ensure each server has isolated credentials'
                    ),
                },
                references=[
                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/",
                ],
                effort="medium",
            ),
            taxonomy=self.taxonomy,
        )