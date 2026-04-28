"""
RPR-CONF-006: Logging, Monitoring, and HITL Gate Configuration Gaps

Detects inadequate observability configurations including incomplete tool call logging,
missing user attribution, absent anomaly detection, insufficient HITL gates, mutable
audit trails, and unredacted PII in logs. These gaps prevent detection of successful
attacks and enable stealth operations.
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


class RprConf006LoggingMonitoringGaps(ReaperCheck):
    """Detect inadequate observability configurations that prevent attack detection."""

    # --- Identity (Contract §2) ---
    check_id = "RPR-CONF-006"
    name = "Logging, Monitoring, and HITL Gate Configuration Gaps"
    description = (
        "Detects inadequate observability configurations including incomplete tool call logging, "
        "missing user attribution, absent anomaly detection, insufficient HITL gates, mutable "
        "audit trails, and unredacted PII in logs. These gaps prevent detection of successful "
        "attacks and enable stealth operations."
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
            entry_id="ASI10",
            justification=(
                "This check directly detects insufficient logging and monitoring capabilities "
                "that prevent detection of security events, which is the core focus of ASI10 "
                "Insufficient Logging & Monitoring."
            ),
        ),
        secondary=[
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-778",
                justification=(
                    "Insufficient logging of security-relevant events maps to CWE-778 "
                    "Insufficient Logging."
                ),
            ),
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-862",
                justification=(
                    "Missing HITL gates on sensitive operations represents missing "
                    "authorization checks, mapping to CWE-862 Missing Authorization."
                ),
            ),
        ],
    )

    # --- Severity (Contract §5) ---
    severity = SeverityRating(
        default="high",
        cvss_base=7.1,
        aarf=None,
    )

    # --- Detection Logic (Contract §6) ---

    # Required fields for complete tool call logging
    REQUIRED_LOG_FIELDS = {
        "tool_id", "operation", "timestamp", "session_id", "response_status"
    }

    # Sensitive operations that require HITL gates
    SENSITIVE_OPERATIONS = {
        "write", "delete", "execute", "send", "create", "modify", "upload"
    }

    # PII patterns that should be redacted in logs
    PII_PATTERNS = {
        "email", "phone", "ssn", "credit_card", "api_key", "token", "password"
    }

    def detect(self, target: TargetConfig) -> Finding | None:
        """Check for six key observability patterns (D6-01 through D6-06)."""
        
        # D6-01: Tool call logging completeness
        logging_issue = self._check_logging_completeness(target)
        if logging_issue:
            return logging_issue

        # D6-02: User attribution
        attribution_issue = self._check_user_attribution(target)
        if attribution_issue:
            return attribution_issue

        # D6-03: Anomaly detection
        anomaly_issue = self._check_anomaly_detection(target)
        if anomaly_issue:
            return anomaly_issue

        # D6-04: HITL gate coverage
        hitl_issue = self._check_hitl_coverage(target)
        if hitl_issue:
            return hitl_issue

        # D6-05: Audit trail immutability
        immutability_issue = self._check_audit_trail_immutability(target)
        if immutability_issue:
            return immutability_issue

        # D6-06: PII redaction
        pii_issue = self._check_pii_redaction(target)
        if pii_issue:
            return pii_issue

        return None

    def _check_logging_completeness(self, target: TargetConfig) -> Finding | None:
        """D6-01: Check for complete tool call logging with required fields."""
        logging_config = target.config.get("logging", {})
        
        # No logging configuration at all
        if not logging_config:
            return self._make_finding(
                observable="No logging configuration present",
                raw_value="config.logging: missing",
                context={"check": "D6-01", "issue": "no_logging_config"},
                file_path=self._resolve_config_path(target),
            )

        # Check for tool call logging specifically
        tool_logging = logging_config.get("tool_calls", {})
        if not tool_logging or not tool_logging.get("enabled", False):
            return self._make_finding(
                observable="Tool call logging is disabled or missing",
                raw_value=f"config.logging.tool_calls: {tool_logging}",
                context={"check": "D6-01", "issue": "tool_logging_disabled"},
                file_path=self._resolve_config_path(target),
            )

        # Check for required fields in tool call logs
        logged_fields = set(tool_logging.get("fields", []))
        missing_fields = self.REQUIRED_LOG_FIELDS - logged_fields
        
        if missing_fields:
            return self._make_finding(
                observable=f"Tool call logging missing required fields: {', '.join(sorted(missing_fields))}",
                raw_value=f"config.logging.tool_calls.fields: {list(logged_fields)}",
                context={"check": "D6-01", "issue": "missing_required_fields", "missing": str(missing_fields)},
                file_path=self._resolve_config_path(target),
            )

        return None

    def _check_user_attribution(self, target: TargetConfig) -> Finding | None:
        """D6-02: Check for user/session attribution in logs."""
        logging_config = target.config.get("logging", {})
        if not logging_config:
            return None  # Already caught by D6-01

        tool_logging = logging_config.get("tool_calls", {})
        logged_fields = set(tool_logging.get("fields", []))

        # Check for attribution fields (user_id is best, session_id acceptable, client_id minimal)
        attribution_fields = {"user_id", "session_id", "client_id"}
        present_attribution = attribution_fields & logged_fields

        if not present_attribution:
            return self._make_finding(
                observable="Tool call logs lack user attribution fields (user_id, session_id, or client_id)",
                raw_value=f"config.logging.tool_calls.fields: {list(logged_fields)}",
                context={"check": "D6-02", "issue": "no_user_attribution"},
                file_path=self._resolve_config_path(target),
            )

        return None

    def _check_anomaly_detection(self, target: TargetConfig) -> Finding | None:
        """D6-03: Check for anomaly detection configuration."""
        monitoring_config = target.config.get("monitoring", {})
        anomaly_config = monitoring_config.get("anomaly_detection", {})

        if not anomaly_config or not anomaly_config.get("enabled", False):
            return self._make_finding(
                observable="Anomaly detection is disabled or missing",
                raw_value=f"config.monitoring.anomaly_detection: {anomaly_config}",
                context={"check": "D6-03", "issue": "no_anomaly_detection"},
                file_path=self._resolve_config_path(target),
            )

        # Check for required anomaly detection categories
        required_categories = {"unusual_tools", "unusual_parameters", "unusual_frequency", "unusual_timing"}
        configured_categories = set(anomaly_config.get("categories", []))
        missing_categories = required_categories - configured_categories

        if missing_categories:
            return self._make_finding(
                observable=f"Anomaly detection missing categories: {', '.join(sorted(missing_categories))}",
                raw_value=f"config.monitoring.anomaly_detection.categories: {list(configured_categories)}",
                context={"check": "D6-03", "issue": "incomplete_anomaly_detection", "missing": str(missing_categories)},
                file_path=self._resolve_config_path(target),
            )

        return None

    def _check_hitl_coverage(self, target: TargetConfig) -> Finding | None:
        """D6-04: Check for HITL gate coverage on sensitive operations."""
        hitl_config = target.config.get("human_in_the_loop", {})
        
        if not hitl_config or not hitl_config.get("enabled", False):
            return self._make_finding(
                observable="Human-in-the-loop (HITL) gates are disabled or missing",
                raw_value=f"config.human_in_the_loop: {hitl_config}",
                context={"check": "D6-04", "issue": "no_hitl_gates"},
                file_path=self._resolve_config_path(target),
            )

        # Check HITL granularity (per-operation is best, per-tool acceptable, per-session insufficient)
        granularity = hitl_config.get("granularity", "").lower()
        if granularity == "session":
            return self._make_finding(
                observable="HITL gates use per-session granularity (insufficient for stealth hijacking defense)",
                raw_value=f"config.human_in_the_loop.granularity: \"{granularity}\"",
                context={"check": "D6-04", "issue": "insufficient_hitl_granularity"},
                file_path=self._resolve_config_path(target),
            )

        # Calculate HITL coverage percentage for sensitive operations
        gated_operations = set(hitl_config.get("operations", []))
        sensitive_ops_in_tools = self._identify_sensitive_operations(target)
        
        if not sensitive_ops_in_tools:
            return None  # No sensitive operations to gate

        covered_sensitive = gated_operations & sensitive_ops_in_tools
        coverage_percentage = len(covered_sensitive) / len(sensitive_ops_in_tools) * 100

        if coverage_percentage < 50:
            return self._make_finding(
                observable=f"HITL coverage of sensitive operations is {coverage_percentage:.0f}% (below 50% threshold)",
                raw_value=f"config.human_in_the_loop.operations: {list(gated_operations)}",
                context={
                    "check": "D6-04", 
                    "issue": "insufficient_hitl_coverage", 
                    "coverage_percent": str(int(coverage_percentage)),
                    "sensitive_operations": str(sensitive_ops_in_tools),
                    "covered_operations": str(covered_sensitive)
                },
                file_path=self._resolve_config_path(target),
            )

        return None

    def _check_audit_trail_immutability(self, target: TargetConfig) -> Finding | None:
        """D6-05: Check for immutable/append-only audit trail storage."""
        logging_config = target.config.get("logging", {})
        storage_config = logging_config.get("storage", {})

        if not storage_config:
            return self._make_finding(
                observable="Audit trail storage configuration is missing",
                raw_value="config.logging.storage: missing",
                context={"check": "D6-05", "issue": "no_storage_config"},
                file_path=self._resolve_config_path(target),
            )

        # Check storage mode
        storage_mode = storage_config.get("mode", "").lower()
        agent_write_access = storage_config.get("agent_write_access", True)  # Default to true for security

        if storage_mode != "append_only" and storage_mode != "immutable":
            if agent_write_access:
                return self._make_finding(
                    observable="Audit trail storage allows agent write access (mutable trail)",
                    raw_value=f"config.logging.storage: mode=\"{storage_mode}\", agent_write_access=true",
                    context={"check": "D6-05", "issue": "mutable_audit_trail"},
                    file_path=self._resolve_config_path(target),
                )

        return None

    def _check_pii_redaction(self, target: TargetConfig) -> Finding | None:
        """D6-06: Check for PII redaction in externally-shipped logs."""
        logging_config = target.config.get("logging", {})
        external_shipping = logging_config.get("external_shipping", {})

        # Only check PII redaction if logs are shipped externally
        if not external_shipping or not external_shipping.get("enabled", False):
            return None

        pii_redaction = external_shipping.get("pii_redaction", {})
        if not pii_redaction or not pii_redaction.get("enabled", False):
            return self._make_finding(
                observable="External log shipping enabled without PII redaction",
                raw_value=f"config.logging.external_shipping.pii_redaction: {pii_redaction}",
                context={"check": "D6-06", "issue": "no_pii_redaction"},
                file_path=self._resolve_config_path(target),
            )

        # Check if critical PII types are configured for redaction
        redacted_types = set(pii_redaction.get("types", []))
        critical_pii = {"api_key", "token", "password"}
        missing_critical = critical_pii - redacted_types

        if missing_critical:
            return self._make_finding(
                observable=f"PII redaction missing critical types: {', '.join(sorted(missing_critical))}",
                raw_value=f"config.logging.external_shipping.pii_redaction.types: {list(redacted_types)}",
                context={
                    "check": "D6-06", 
                    "issue": "incomplete_pii_redaction", 
                    "missing_critical": str(missing_critical)
                },
                file_path=self._resolve_config_path(target),
            )

        return None

    def _identify_sensitive_operations(self, target: TargetConfig) -> set[str]:
        """Identify sensitive operations available in the target's tools."""
        sensitive_ops = set()
        
        for tool in target.tools:
            tool_name = tool.get("name", "")
            tool_operations = tool.get("operations", [])
            
            # Check tool scope for sensitive operations
            for op in tool_operations:
                op_name = op.get("name", "").lower()
                if any(sensitive in op_name for sensitive in self.SENSITIVE_OPERATIONS):
                    sensitive_ops.add(op_name)
            
            # Check if tool name itself indicates sensitive operations
            if any(sensitive in tool_name.lower() for sensitive in self.SENSITIVE_OPERATIONS):
                sensitive_ops.add(tool_name.lower())

        return sensitive_ops

    def _make_finding(
        self,
        observable: str,
        raw_value: str,
        context: dict[str, str],
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
                context=context,
            ),
            remediation=Remediation(
                description=(
                    "Configure comprehensive logging with attribution, implement HITL gates "
                    "on sensitive operations, ensure immutable audit trails, and add PII "
                    "redaction for external log shipping."
                ),
                steps={
                    "openclaw": (
                        "1. Enable complete tool call logging in ~/.openclaw/config.json:\n"
                        '  "logging": {\n'
                        '    "tool_calls": {\n'
                        '      "enabled": true,\n'
                        '      "fields": ["tool_id", "operation", "parameters", "timestamp", "session_id", "user_id", "response_status"]\n'
                        '    },\n'
                        '    "storage": {"mode": "append_only", "agent_write_access": false}\n'
                        '  }\n'
                        "2. Add HITL gates for sensitive operations:\n"
                        '  "human_in_the_loop": {\n'
                        '    "enabled": true,\n'
                        '    "granularity": "operation",\n'
                        '    "operations": ["write", "delete", "execute", "send"]\n'
                        '  }\n'
                        "3. Configure anomaly detection and PII redaction as needed."
                    ),
                    "langchain": (
                        "1. Configure LangSmith with complete parameter capture:\n"
                        "   - Set LANGSMITH_TRACING=true\n"
                        "   - Include user_id in trace metadata\n"
                        "2. Add HumanApprovalCallbackHandler to sensitive tools:\n"
                        "   callback = HumanApprovalCallbackHandler()\n"
                        "   sensitive_tool.callback_manager.add_handler(callback)\n"
                        "3. Configure immutable log storage with append-only mode.\n"
                        "4. Add PII redaction filters before external shipping."
                    ),
                    "crewai": (
                        "1. Enable crew-level logging in crew configuration:\n"
                        '  crew = Crew(\n'
                        '    logging_enabled=True,\n'
                        '    log_fields=["tool_id", "operation", "timestamp", "user_id"],\n'
                        '    audit_storage="append_only"\n'
                        '  )\n'
                        "2. Add human_input flag to sensitive tasks:\n"
                        '  task = Task(\n'
                        '    description="...",\n'
                        '    human_input=True  # For write/delete/execute operations\n'
                        '  )\n'
                        "3. Configure anomaly detection rules for unusual patterns."
                    ),
                    "universal": (
                        "1. Implement comprehensive tool call logging with required fields:\n"
                        "   - tool_id, operation, parameters/hash, timestamp, session_id, response_status\n"
                        "   - Add user_id or session_id for attribution\n"
                        "2. Configure HITL gates on ALL sensitive operations (write, delete, execute, send)\n"
                        "   - Use per-operation granularity, never per-session\n"
                        "3. Set up immutable/append-only log storage\n"
                        "4. Add anomaly detection for unusual tools, parameters, frequency, timing\n"
                        "5. Implement PII redaction for externally-shipped logs"
                    ),
                },
                references=[
                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/",
                    "https://owasp.org/www-project-logging-guide/",
                ],
                effort="medium",
            ),
            taxonomy=self.taxonomy,
        )

    def _resolve_config_path(self, target: TargetConfig) -> str | None:
        """Resolve the main configuration file path for this framework."""
        framework_paths = {
            "openclaw": "~/.openclaw/config.json",
            "langchain": "langchain_config.yaml", 
            "crewai": "crew_config.yaml",
        }
        
        return target.metadata.get("config_path") or framework_paths.get(target.framework, "agent_config.json")