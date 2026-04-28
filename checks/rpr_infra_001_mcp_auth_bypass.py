"""
RPR-INFRA-001: MCP Server Authentication Bypass

Actively probes MCP server endpoints to verify authentication enforcement.
Complements RPR-CONF-001 (static auth config check) by actually connecting
to the server and testing whether unauthenticated requests are accepted.
"""

from __future__ import annotations

from reaper.sdk import (
    Evidence,
    Finding,
    ProbeResponse,
    ProbeTarget,
    ReaperCheck,
    Remediation,
    SessionContext,
    SeverityRating,
    TargetConfig,
    TaxonomyEntry,
    TaxonomyMapping,
)


class RprInfra001McpAuthBypass(ReaperCheck):
    """Probe MCP servers to verify authentication is enforced at runtime."""

    # --- Identity (Contract §2) ---
    check_id = "RPR-INFRA-001"
    name = "MCP Server Authentication Bypass"
    description = (
        "Actively probes MCP server endpoints to verify authentication enforcement. "
        "Tests whether the server accepts unauthenticated connections, invalid tokens, "
        "and unauthenticated tool invocations. RPR-CONF-001 detects missing auth in "
        "configuration; this check confirms whether the server actually rejects "
        "unauthenticated requests at runtime."
    )
    contract_version = "2.0"

    # --- Classification (Contract §3) ---
    category = "infra"
    wedge = 2
    tier = "community"
    frameworks = ["mcp_generic", "openclaw"]
    check_type = "deterministic"

    # --- Taxonomy (Contract §4) ---
    taxonomy = TaxonomyMapping(
        primary=TaxonomyEntry(
            framework="owasp_asi",
            entry_id="ASI04",
            justification=(
                "ASI04 covers supply chain risks from unauthenticated or poorly "
                "authenticated components. An MCP server that accepts unauthenticated "
                "requests allows any client to invoke tools without identity verification."
            ),
        ),
        secondary=[
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-306",
                justification=(
                    "Missing Authentication for Critical Function — the MCP server "
                    "performs critical operations (tool invocation) without requiring "
                    "authentication from the caller."
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

    def detect(self, target: TargetConfig) -> Finding | None:
        """Wedge 1 path — not used for this check."""
        return None

    def probe(self, target: ProbeTarget, session: SessionContext) -> Finding | None:
        """Probe the MCP server to test authentication enforcement."""

        # Probe 1: Unauthenticated access — connect with NO credentials
        no_auth_target = ProbeTarget(
            endpoint=target.endpoint,
            transport=target.transport,
            server_name=target.server_name,
            auth_context={},  # No credentials
            metadata=target.metadata,
        )
        result = session.mcp_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "reaper-probe", "version": "0.2.0"},
        }, target=no_auth_target)

        if result.status == "success":
            # Server accepted without auth — try tools/list to confirm access
            tools_result = session.mcp_request("tools/list", {}, target=no_auth_target)
            if tools_result.status == "success":
                return self._make_finding(
                    observable=(
                        f"MCP server '{target.server_name}' accepted unauthenticated "
                        f"initialize + tools/list request"
                    ),
                    raw_value=f"tools/list response: {tools_result.body}",
                    target=target,
                    probe_result=tools_result,
                    severity="critical",
                )

        # Probe 2: Invalid token — connect with deliberately bad credentials
        bad_auth_target = ProbeTarget(
            endpoint=target.endpoint,
            transport=target.transport,
            server_name=target.server_name,
            auth_context={"type": "bearer", "token": "REAPER-INVALID-TOKEN-PROBE"},
            metadata=target.metadata,
        )
        result = session.mcp_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "reaper-probe",
                "version": "0.2.0",
                "auth_token": "REAPER-INVALID-TOKEN-PROBE",
            },
        }, target=bad_auth_target)

        if result.status == "success":
            return self._make_finding(
                observable=(
                    f"MCP server '{target.server_name}' accepted invalid "
                    f"authentication token"
                ),
                raw_value="Token 'REAPER-INVALID-TOKEN-PROBE' was accepted",
                target=target,
                probe_result=result,
                severity="high",
            )

        # Probe 3: Tool invocation without auth
        no_auth_tool_target = ProbeTarget(
            endpoint=target.endpoint,
            transport=target.transport,
            server_name=target.server_name,
            auth_context={},
            metadata=target.metadata,
        )
        result = session.mcp_request(
            "tools/call",
            {"name": "_probe", "arguments": {}},
            target=no_auth_tool_target,
        )

        if result.status == "success":
            return self._make_finding(
                observable=(
                    f"MCP server '{target.server_name}' accepted unauthenticated "
                    f"tool invocation"
                ),
                raw_value=f"tools/call response: {result.body}",
                target=target,
                probe_result=result,
                severity="high",
            )

        # All probes rejected — server enforces auth
        return None

    def _make_finding(
        self,
        observable: str,
        raw_value: str,
        target: ProbeTarget,
        probe_result: ProbeResponse,
        severity: str,
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=severity,
            confidence="high",
            evidence=Evidence(
                observable=observable,
                file_path=None,
                line=None,
                line_end=None,
                raw_value=raw_value,
                context={
                    "server_name": target.server_name,
                    "endpoint": target.endpoint,
                    "transport": target.transport,
                    "probe_elapsed_ms": str(probe_result.elapsed_ms),
                },
            ),
            remediation=Remediation(
                description=(
                    "Configure the MCP server to require authentication for all "
                    "requests. Use bearer tokens, mTLS, or API keys. Reject "
                    "unauthenticated connections before processing any methods."
                ),
                steps={
                    "mcp_generic": (
                        "Configure MCP server authentication:\n"
                        '1. Set auth requirement: "auth": {"type": "bearer", "required": true}\n'
                        "2. Generate and distribute API keys or tokens to authorized clients\n"
                        "3. Validate tokens on every request, not just initialize\n"
                        "4. Return JSON-RPC error -32001 for unauthenticated requests"
                    ),
                    "openclaw": (
                        "In OpenClaw server configuration:\n"
                        "1. Enable auth in server config: auth.required = true\n"
                        "2. Configure token validation: auth.tokens = [list of valid tokens]\n"
                        "3. Ensure auth is checked on all MCP methods, not just initialize"
                    ),
                },
                references=[
                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/",
                ],
                effort="low",
            ),
            taxonomy=self.taxonomy,
        )
