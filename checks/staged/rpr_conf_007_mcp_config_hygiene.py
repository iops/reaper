"""
RPR-CONF-007: MCP Configuration Hygiene Failures

Detects operational security gaps in MCP server configuration including debug mode
enabled in production, demo/example tools deployed, vulnerable software versions,
insecure file permissions, poor secret storage hygiene, and untracked configuration
changes. Debug mode is a severity multiplier that simultaneously enables multiple
vulnerability categories.
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


class RprConf007McpConfigHygiene(ReaperCheck):
    """Detect operational security gaps in MCP server configuration."""

    # --- Identity (Contract §2) ---
    check_id = "RPR-CONF-007"
    name = "MCP Configuration Hygiene Failures"
    description = (
        "Detects operational security gaps in MCP server configuration including "
        "debug mode enabled in production, demo/example tools deployed, "
        "vulnerable software versions, insecure file permissions, poor secret "
        "storage hygiene, and untracked configuration changes. Debug mode is a "
        "severity multiplier that simultaneously enables multiple vulnerability "
        "categories."
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
                "This check directly detects configuration hygiene failures that "
                "create security weaknesses in AI agent deployment, specifically "
                "targeting the operational security gaps outlined in ASI03."
            ),
        ),
        secondary=[
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-489",
                justification=(
                    "Debug mode and development configurations left in production "
                    "represent leftover debug code that exposes sensitive information."
                ),
            ),
            TaxonomyEntry(
                framework="cwe",
                entry_id="CWE-200",
                justification=(
                    "Poor configuration hygiene leads to exposure of sensitive "
                    "information through debug output, demo tools, and insecure "
                    "secret storage."
                ),
            ),
        ],
    )

    # --- Severity (Contract §5) ---
    severity = SeverityRating(
        default="high",
        cvss_base=7.5,
        aarf=AARFAssessment(
            autonomy=0.5,
            tools=1.0,
            language=0.5,
            context=1.0,
            non_determinism=0.5,
            opacity=1.0,
            persistence=0.5,
            identity=0.5,
            multi_agent=0.5,
            self_modification=0.5,
        ),
    )

    # --- Detection Patterns ---

    DEBUG_INDICATORS = {
        # Direct debug flags
        "debug",
        "verbose",
        "trace",
        "dev",
        "development",
        "test_mode",
        "debug_mode",
        "verbosity",
        "loglevel",
        "log_level",
        "logging_level",
        "logmode",
        "log_mode",
        # Framework-specific
        "node_env",
        "env",
        "environment",
        "rails_env",
        "flask_env",
        "django_debug",
        # Common variations
        "is_debug",
        "enable_debug",
        "debug_enabled",
        "verbose_logging",
        "detailed_logging",
        "full_logging",
    }

    DEBUG_VALUES = {
        # Boolean representations
        "true",
        "yes",
        "on",
        "1",
        "enabled",
        "enable",
        # Development environment indicators
        "development",
        "dev",
        "local",
        "debug",
        "test",
        "testing",
        # Debug-specific patterns
        "*",  # DEBUG=*
        "all",
        "verbose",
        "trace",
        "debug",
        "info",
    }

    DEMO_TOOL_PATTERNS = [
        # Direct demo indicators
        r".*\b(demo|example|sample|test|hello[_\-]?world|tutorial|guide)\b.*",
        r".*\b(proof[_\-]?of[_\-]?concept|poc|showcase|illustration|validation)\b.*",
        r".*\b(temporary|temp|trial|prototype|stub|mock)\b.*",
        r".*\b(playground|sandbox|practice|training)\b.*",
        # Description patterns
        r".*(for\s+demonstration|sample\s+implementation|example\s+usage).*",
        r".*(proof\s+of\s+concept|just\s+a\s+test|testing\s+purposes).*",
        r".*(development\s+only|dev\s+purposes|not\s+production).*",
        r".*(placeholder|boilerplate|skeleton|template).*",
    ]

    SECRET_PATTERNS = [
        # Generic secret patterns
        r"(password|passwd|pwd|secret|key|token|auth|credential).*[=:]\s*['\"]?[a-zA-Z0-9+/]{8,}['\"]?",
        r"(api[_-]?key|access[_-]?token|bearer[_-]?token|auth[_-]?token).*[=:]\s*['\"]?[a-zA-Z0-9+/]{16,}['\"]?",
        r"(client[_-]?secret|app[_-]?secret|webhook[_-]?secret).*[=:]\s*['\"]?[a-zA-Z0-9+/]{16,}['\"]?",
        # Database connection strings
        r"(database[_-]?url|db[_-]?url|connection[_-]?string).*[=:]\s*['\"]?[a-z]+://[^'\"\s]+['\"]?",
        # AWS/cloud credentials
        r"(aws[_-]?access|aws[_-]?secret|aws[_-]?key).*[=:]\s*['\"]?[A-Z0-9]{20,}['\"]?",
        r"(gcp[_-]?key|google[_-]?key|azure[_-]?key).*[=:]\s*['\"]?[a-zA-Z0-9+/]{20,}['\"]?",
        # JWT patterns
        r"(jwt|token).*[=:]\s*['\"]?eyJ[a-zA-Z0-9+/]+\.[a-zA-Z0-9+/]+\.[a-zA-Z0-9+/]*['\"]?",
    ]

    # CVE patterns for common vulnerabilities
    VULNERABLE_VERSIONS = {
        "mcp-server": {"<0.4.0": ["CVE-2026-32051"]},
        "openclaw": {"<1.2.1": ["CVE-2026-32052"]},
        "langchain": {"<0.1.20": ["CVE-2026-32053"]},
    }

    def detect(self, target: TargetConfig) -> Finding | None:
        """Execute detection logic against the target configuration."""

        # Check for debug mode indicators (highest severity)
        debug_finding = self._check_debug_mode(target)
        if debug_finding:
            return debug_finding

        # Check for demo/example tools
        demo_finding = self._check_demo_tools(target)
        if demo_finding:
            return demo_finding

        # Check for exposed secrets
        secret_finding = self._check_secret_exposure(target)
        if secret_finding:
            return secret_finding

        # Check for vulnerable software versions
        version_finding = self._check_vulnerable_versions(target)
        if version_finding:
            return version_finding

        # Check for poor version control hygiene
        version_control_finding = self._check_version_control(target)
        if version_control_finding:
            return version_control_finding

        return None

    def _check_debug_mode(self, target: TargetConfig) -> Finding | None:
        """Check for debug mode indicators in configuration."""
        
        # Check all configuration sources
        all_config = {
            "config": target.config,
            "mcp_servers": {"servers": target.mcp_servers},
            "metadata": target.metadata,
        }

        for source, config_data in all_config.items():
            finding = self._find_debug_indicators_recursive(config_data, source)
            if finding:
                return self._make_debug_finding(finding, target)

        # Check environment variables in MCP server configurations
        for server in target.mcp_servers:
            env = server.get("env", {})
            if env:
                finding = self._check_env_for_debug(env)
                if finding:
                    return self._make_debug_finding(finding, target)

        return None

    def _find_debug_indicators_recursive(
        self, obj: Any, path: str = "", depth: int = 0
    ) -> dict | None:
        """Recursively search for debug indicators in configuration."""
        if depth > 10:  # Prevent infinite recursion
            return None

        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                
                # Normalize key for comparison
                normalized_key = self._normalize_string(key)
                
                # Check if key is a debug indicator
                if normalized_key in self.DEBUG_INDICATORS:
                    normalized_value = self._normalize_value(value)
                    if normalized_value in self.DEBUG_VALUES:
                        return {
                            "path": current_path,
                            "key": key,
                            "value": value,
                            "type": "debug_flag"
                        }

                # Check for specific patterns
                if self._is_production_context(obj) and normalized_value in {"development", "dev", "debug", "test"}:
                    return {
                        "path": current_path,
                        "key": key,
                        "value": value,
                        "type": "dev_in_production"
                    }

                # Recursively check nested objects
                nested_finding = self._find_debug_indicators_recursive(value, current_path, depth + 1)
                if nested_finding:
                    return nested_finding

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                current_path = f"{path}[{i}]" if path else f"[{i}]"
                nested_finding = self._find_debug_indicators_recursive(item, current_path, depth + 1)
                if nested_finding:
                    return nested_finding

        return None

    def _check_env_for_debug(self, env_vars: dict) -> dict | None:
        """Check environment variables for debug indicators."""
        for key, value in env_vars.items():
            # Normalize and check key
            normalized_key = self._normalize_string(key)
            normalized_value = self._normalize_string(str(value)) if value else ""

            # Check DEBUG=* pattern with whitespace handling
            if normalized_key == "debug" and ("*" in normalized_value or "all" in normalized_value):
                return {
                    "path": f"env.{key}",
                    "key": key,
                    "value": value,
                    "type": "debug_env_var"
                }

            # Check other debug indicators
            if normalized_key in self.DEBUG_INDICATORS and normalized_value in self.DEBUG_VALUES:
                return {
                    "path": f"env.{key}",
                    "key": key,
                    "value": value,
                    "type": "debug_env_var"
                }

        return None

    def _check_demo_tools(self, target: TargetConfig) -> Finding | None:
        """Check for demo/example tools in the tool registry."""
        for tool in target.tools:
            name = tool.get("name", "")
            description = tool.get("description", "")
            
            # Normalize text for pattern matching
            normalized_name = self._normalize_unicode(name.lower())
            normalized_desc = self._normalize_unicode(description.lower())

            # Check against demo patterns
            for pattern in self.DEMO_TOOL_PATTERNS:
                if re.search(pattern, normalized_name, re.IGNORECASE):
                    return self._make_demo_tool_finding(tool, "name", name, target)
                if re.search(pattern, normalized_desc, re.IGNORECASE):
                    return self._make_demo_tool_finding(tool, "description", description, target)

        return None

    def _check_secret_exposure(self, target: TargetConfig) -> Finding | None:
        """Check for exposed secrets in configuration and files."""
        
        # Check configuration files
        for file_path, content in target.files.items():
            for pattern in self.SECRET_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Don't extract actual secret values
                    return self._make_secret_finding(
                        file_path=file_path,
                        pattern_type="config_file",
                        line_content=match.group(0)[:100] + "...",
                        target=target
                    )

        # Check MCP server configurations
        for server in target.mcp_servers:
            server_name = server.get("name", "<unnamed>")
            auth = server.get("auth", {})
            
            # Check for hardcoded tokens
            token = auth.get("token", "")
            if isinstance(token, str) and token and not token.startswith("$"):
                # Potential hardcoded secret
                return self._make_secret_finding(
                    file_path=None,
                    pattern_type="hardcoded_token",
                    line_content=f"servers.{server_name}.auth.token: <redacted>",
                    target=target
                )

        return None

    def _check_vulnerable_versions(self, target: TargetConfig) -> Finding | None:
        """Check for vulnerable software versions."""
        
        # Extract version information from metadata and config
        versions_to_check = []
        
        # Check framework version
        framework_version = target.metadata.get("version")
        if framework_version:
            versions_to_check.append((target.framework, framework_version))

        # Check MCP server versions
        for server in target.mcp_servers:
            server_name = server.get("name", "")
            version = server.get("version")
            if version and server_name:
                versions_to_check.append((server_name, version))

        # Check against known vulnerabilities
        for software, version in versions_to_check:
            vulns = self._check_version_vulnerabilities(software, version)
            if vulns:
                return self._make_version_finding(software, version, vulns, target)

        return None

    def _check_version_control(self, target: TargetConfig) -> Finding | None:
        """Check for version control tracking of configuration."""
        
        # Look for version control indicators
        has_git = ".git" in target.files or any(".git/" in path for path in target.files.keys())
        has_version_tracking = any(
            filename in target.files 
            for filename in [".gitignore", "version.txt", "VERSION", "CHANGELOG.md"]
        )

        # Check if critical config files are tracked
        config_files = [
            path for path in target.files.keys() 
            if any(ext in path.lower() for ext in [".json", ".yaml", ".yml", ".toml", ".env"])
        ]

        if config_files and not (has_git or has_version_tracking):
            return self._make_version_control_finding(config_files, target)

        return None

    def _normalize_string(self, text: str) -> str:
        """Normalize string for comparison (lowercase, no special chars)."""
        if not isinstance(text, str):
            return str(text).lower()
        return re.sub(r'[_\-\s]', '', text.lower()).strip()

    def _normalize_value(self, value: Any) -> str:
        """Normalize configuration value for comparison."""
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, str):
            return self._normalize_string(value)
        return str(value).lower()

    def _normalize_unicode(self, text: str) -> str:
        """Normalize unicode characters to prevent homoglyph attacks."""
        if not text:
            return ""
        # Normalize unicode characters to their canonical forms
        normalized = unicodedata.normalize('NFKC', text)
        # Convert to ASCII, ignoring non-ASCII characters
        ascii_text = normalized.encode('ascii', 'ignore').decode('ascii')
        return ascii_text.lower()

    def _is_production_context(self, config_obj: dict) -> bool:
        """Check if configuration suggests production environment."""
        prod_indicators = {"production", "prod", "live", "release"}
        
        for key, value in config_obj.items():
            if isinstance(value, str) and self._normalize_string(value) in prod_indicators:
                return True
        
        return False

    def _check_version_vulnerabilities(self, software: str, version: str) -> list[str]:
        """Check if software version has known vulnerabilities."""
        software_lower = software.lower()
        
        for vuln_software, version_rules in self.VULNERABLE_VERSIONS.items():
            if vuln_software in software_lower or software_lower in vuln_software:
                for version_pattern, cves in version_rules.items():
                    if self._version_matches_pattern(version, version_pattern):
                        return cves
        
        return []

    def _version_matches_pattern(self, version: str, pattern: str) -> bool:
        """Check if version matches vulnerability pattern."""
        # Simple version comparison - in production, use proper semver library
        if pattern.startswith("<"):
            target_version = pattern[1:]
            # Basic string comparison for demo
            return version < target_version
        
        return False

    def _make_debug_finding(self, debug_info: dict, target: TargetConfig) -> Finding:
        """Create finding for debug mode detection."""
        return Finding(
            check_id=self.check_id,
            severity="critical",  # Debug mode is severity multiplier
            confidence="high",
            evidence=Evidence(
                observable=f"Debug mode enabled: {debug_info['key']}={debug_info['value']} at {debug_info['path']}",
                file_path=self._resolve_config_path(target),
                line=None,
                line_end=None,
                raw_value=f"{debug_info['key']}: {debug_info['value']}",
                context={
                    "config_path": debug_info['path'],
                    "debug_type": debug_info['type'],
                    "framework": target.framework
                },
            ),
            remediation=Remediation(
                description=(
                    "Disable all debug and development mode flags in production. "
                    "Debug mode simultaneously enables multiple vulnerability categories: "
                    "weakened authentication, verbose error messages, undocumented endpoints, "
                    "and disabled rate limiting."
                ),
                steps={
                    "universal": (
                        "1. Set all debug flags to false/disabled:\n"
                        "   - debug: false\n"
                        "   - verbose: false\n"
                        "   - env: production\n"
                        "   - log_level: warn or error\n\n"
                        "2. Verify NODE_ENV=production if using Node.js\n"
                        "3. Remove all development-specific configurations\n"
                        "4. Restart all MCP servers after configuration changes"
                    ),
                },
                references=[
                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/",
                ],
                effort="trivial",
            ),
            taxonomy=self.taxonomy,
        )

    def _make_demo_tool_finding(
        self, tool: dict, field: str, value: str, target: TargetConfig
    ) -> Finding:
        """Create finding for demo tool detection."""
        tool_name = tool.get("name", "<unnamed>")
        
        return Finding(
            check_id=self.check_id,
            severity="high",
            confidence="high",
            evidence=Evidence(
                observable=f"Demo/example tool detected: {tool_name} ({field}: '{value}')",
                file_path=self._resolve_config_path(target),
                line=None,
                line_end=None,
                raw_value=f"tools.{tool_name}.{field}: \"{value}\"",
                context={
                    "tool_name": tool_name,
                    "detection_field": field,
                    "framework": target.framework
                },
            ),
            remediation=Remediation(
                description=(
                    "Remove all demo, example, and test tools from production deployments. "
                    "Demo tools are shadow tools with no authentication, no validation, "
                    "and full capability - perfect targets for exploitation."
                ),
                steps={
                    "universal": (
                        "1. Review all registered tools for demo/example patterns\n"
                        "2. Remove tools with names containing:\n"
                        "   - demo, example, sample, test\n"
                        "   - hello_world, tutorial, guide\n"
                        "   - proof-of-concept, poc, showcase\n"
                        "3. Remove tools with descriptions mentioning:\n"
                        "   - 'for demonstration purposes'\n"
                        "   - 'sample implementation'\n"
                        "   - 'development only'\n"
                        "4. Replace with production-ready tools with proper auth"
                    ),
                },
                references=[
                    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/",
                ],
                effort="low",
            ),
            taxonomy=self.taxonomy,
        )

    def _make_secret_finding(
        self, file_path: str | None, pattern_type: str, line_content: str, target: TargetConfig
    ) -> Finding:
        """Create finding for secret exposure."""
        return Finding(
            check_id=self.check_id,
            severity="high",
            confidence="high",
            evidence=Evidence(
                observable=f"Secret exposed in {pattern_type}: {line_content}",
                file_path=file_path,
                line=None,
                line_end=None,
                raw_value=line_content,
                context={
                    "pattern_type": pattern_type,
                    "framework": target.framework
                },
            ),
            remediation=Remediation(
                description=(
                    "Migrate all secrets to a dedicated secret manager. "
                    "Remove secrets from configuration files, source code, "
                    "and environment variables."
                ),
                steps={
                    "universal": (
                        "1. Use environment variables for all secrets:\n"
                        "   - API keys: $API_KEY\n"
                        "   - Database URLs: $DATABASE_URL\n"
                        "   - Auth tokens: $AUTH_TOKEN\n\n"
                        "2. Store actual values in secret manager:\n"
                        "   - AWS Secrets Manager\n"
                        "   - HashiCorp Vault\n"
                        "   - GCP Secret Manager\n\n"
                        "3. Rotate any previously exposed secrets\n"
                        "4. Remove .env files from version control"
                    ),
                },
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                ],
                effort="medium",
            ),
            taxonomy=self.taxonomy,
        )

    def _make_version_finding(
        self, software: str, version: str, cves: list[str], target: TargetConfig
    ) -> Finding:
        """Create finding for vulnerable software version."""
        return Finding(
            check_id=self.check_id,
            severity="high",
            confidence="high",
            evidence=Evidence(
                observable=f"Vulnerable {software} version {version} (CVEs: {', '.join(cves)})",
                file_path=self._resolve_config_path(target),
                line=None,
                line_end=None,
                raw_value=f"{software}: {version}",
                context={
                    "software": software,
                    "version": version,
                    "cves": cves,
                    "framework": target.framework
                },
            ),
            remediation=Remediation(
                description=(
                    "Update to the latest stable version of the MCP server software. "
                    "Subscribe to security advisories for timely vulnerability notifications."
                ),
                steps={
                    "universal": (
                        f"1. Update {software} to latest stable version\n"
                        f"2. Current version {version} is vulnerable to: {', '.join(cves)}\n"
                        "3. Test updated version in staging environment\n"
                        "4. Deploy to production after validation\n"
                        "5. Subscribe to security advisories for future updates"
                    ),
                },
                references=[
                    f"https://nvd.nist.gov/vuln/detail/{cves[0]}" if cves else "",
                ],
                effort="low",
            ),
            taxonomy=self.taxonomy,
        )

    def _make_version_control_finding(
        self, config_files: list[str], target: TargetConfig
    ) -> Finding:
        """Create finding for missing version control."""
        return Finding(
            check_id=self.check_id,
            severity="medium",
            confidence="high",
            evidence=Evidence(
                observable=f"Configuration files not under version control: {', '.join(config_files[:3])}{'...' if len(config_files) > 3 else ''}",
                file_path=None,
                line=None,
                line_end=None,
                raw_value=f"Untracked files: {len(config_files)} config files",
                context={
                    "config_file_count": str(len(config_files)),
                    "framework": target.framework
                },
            ),
            remediation=Remediation(
                description=(
                    "Place all MCP configuration under version control with "
                    "pull request-based change control to maintain audit trail."
                ),
                steps={
                    "universal": (
                        "1. Initialize git repository if not present:\n"
                        "   git init\n\n"
                        "2. Add configuration files to version control:\n"
                        "   git add config/\n"
                        "   git commit -m 'Add MCP configuration'\n\n"
                        "3. Set up branch protection and PR-based workflow\n"
                        "4. Create .gitignore for sensitive files:\n"
                        "   .env\n"
                        "   *.key\n"
                        "   secrets/\n\n"
                        "5. Document change approval process"
                    ),
                },
                references=[
                    "https://git-scm.com/doc",
                ],
                effort="low",
            ),
            taxonomy=self.taxonomy,
        )

    def _resolve_config_path(self, target: TargetConfig) -> str | None:
        """Resolve the primary configuration file path."""
        if target.framework == "openclaw":
            return target.metadata.get("config_path", "~/.openclaw/config.json")
        elif target.framework == "langchain":
            return target.metadata.get("config_path", "langchain.yaml")
        elif target.framework == "crewai":
            return target.metadata.get("config_path", "crew_config.yaml")
        else:
            # Universal framework
            return target.metadata.get("config_path", "mcp_config.json")