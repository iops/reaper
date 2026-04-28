"""
RPR-CONF-001: MCP Server Missing Authentication

Detects MCP servers configured without authentication. An unauthenticated
MCP server allows any client to invoke tools, read agent state, and
exfiltrate data without credentials.
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


class RprConf001McpAuth(ReaperCheck):
    """Detect MCP servers with missing or ineffective authentication."""

    # --- Identity (Contract §2) ---
    check_id = "RPR-CONF-001"
    name = "MCP Server Missing Authentication"
    description = (
        "Detects MCP servers configured without authentication. "
        "An unauthenticated MCP server allows any client to invoke tools, "
        "read agent state, and exfiltrate data without credentials. "
        "This was the attack vector in the postmark-mcp incident "
        "(1,643 downloads before removal)."
    )
    contract_version = "1.0"

    # --- Classification (Contract §3) ---
    category = "config"
    wedge = 1
    tier = "community"
    frameworks = ["openclaw", "mcp_generic"]
    check_type = "deterministic"

    # --- Taxonomy (Contract §4) ---
    taxonomy = TaxonomyMapping(
        primary=TaxonomyEntry(
            framework="owasp_asi",
            entry_id="ASI04",
            justification=(
                "Detects unsigned, unauthenticated MCP server connections "
                "loaded at runtime — the supply chain injection vector "
                "described by ASI04 where runtime-loaded components lack "
                "integrity verification."
            ),
        ),
        secondary=[
            TaxonomyEntry(
                framework="mitre_atlas",
                entry_id="AML.T0098",
                justification=(
                    "No credential barrier to tool access — maps to "
                    "AI Agent Tool Credential Harvesting where the "
                    "harvesting is trivial because no credential exists."
                ),
            ),
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-306",
                justification=(
                    "Missing Authentication for Critical Function — "
                    "the MCP server endpoint is a critical function "
                    "(tool invocation) with no authentication."
                ),
            ),
        ],
    )

    # --- Severity (Contract §5) ---
    severity = SeverityRating(
        default="high",
        cvss_base=8.2,
        aarf=None,
    )

    # --- Detection Logic (Contract §6) ---

    PLACEHOLDER_TOKENS = {
        "changeme", "token", "xxx", "placeholder", "test",
        "todo", "fixme", "replace_me", "your_token_here",
    }

    def detect(self, target: TargetConfig) -> Finding | None:
        """Check each MCP server declaration for missing or broken auth."""
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            auth = server.get("auth")

            # CASE 1: No auth key at all
            if auth is None:
                return self._make_finding(
                    server_name=server_name,
                    observable=f"auth key absent from MCP server '{server_name}' config",
                    raw_value=f"servers.{server_name}: no 'auth' key present",
                    file_path=self._resolve_config_path(target),
                )

            # CASE 2: Auth explicitly disabled
            auth_type = auth.get("type", "").lower()
            if auth_type == "none":
                return self._make_finding(
                    server_name=server_name,
                    observable=f"MCP server '{server_name}' has auth.type set to 'none'",
                    raw_value=f'servers.{server_name}.auth.type: "none"',
                    file_path=self._resolve_config_path(target),
                )

            # CASE 3: Auth present but token is empty or placeholder
            token = auth.get("token", "")
            if isinstance(token, str):
                token_stripped = token.strip()
                if token_stripped == "":
                    return self._make_finding(
                        server_name=server_name,
                        observable=f"MCP server '{server_name}' has empty auth token",
                        raw_value=f'servers.{server_name}.auth.token: ""',
                        file_path=self._resolve_config_path(target),
                    )
                if token_stripped.lower() in self.PLACEHOLDER_TOKENS:
                    return self._make_finding(
                        server_name=server_name,
                        observable=(
                            f"MCP server '{server_name}' has placeholder auth token: "
                            f"'{token_stripped}'"
                        ),
                        raw_value=f'servers.{server_name}.auth.token: "{token_stripped}"',
                        file_path=self._resolve_config_path(target),
                    )

        return None

    def _make_finding(
        self,
        server_name: str,
        observable: str,
        raw_value: str,
        file_path: str | None,
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=self.severity.default,
            confidence="high",
            evidence=Evidence(
                observable=observable,
                file_path=file_path,
                line=None,
                line_end=None,
                raw_value=raw_value,
                context={"mcp_server": server_name},
            ),
            remediation=Remediation(
                description=(
                    "Configure authentication for the MCP server. "
                    "Use bearer token auth at minimum. Tokens MUST "
                    "reference environment variables, not literal values."
                ),
                steps={
                    "openclaw": (
                        'In ~/.openclaw/config.json, under '
                        'servers.<server-name>, add:\n'
                        '  "auth": {\n'
                        '    "type": "bearer",\n'
                        '    "token": "$MCP_AUTH_TOKEN"\n'
                        '  }\n'
                        'Set the MCP_AUTH_TOKEN environment variable '
                        'to a cryptographically random value (32+ chars).'
                    ),
                    "mcp_generic": (
                        'Configure your MCP server transport with '
                        'authentication. For SSE transport, add an '
                        'Authorization header. For stdio transport, '
                        'use the server\'s native auth mechanism. '
                        'Tokens MUST be sourced from environment '
                        'variables, not config files.'
                    ),
                },
                references=[
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                ],
                effort="trivial",
            ),
            taxonomy=self.taxonomy,
        )

    def _resolve_config_path(self, target: TargetConfig) -> str | None:
        if target.framework == "openclaw":
            return target.metadata.get("config_path", "~/.openclaw/config.json")
        return None
