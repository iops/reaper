"""
REAPER SDK — Base classes and data types for detection checks.

Implements Check Contract v1.0 (Wedge 1 static analysis)
and v2.0 extensions (Wedge 2 active infrastructure probing).
Check authors import from this module only.
"""

from __future__ import annotations

import logging
import asyncio
import time as _time
from dataclasses import dataclass, field
from uuid import uuid4

logger = logging.getLogger("reaper")

# ---------------------------------------------------------------------------
# Taxonomy (Contract §4)
# ---------------------------------------------------------------------------

TAXONOMY_FRAMEWORKS = {"owasp_asi", "mitre_atlas", "cwe", "owasp_llm", "mcp_advisory"}


@dataclass
class TaxonomyEntry:
    framework: str
    entry_id: str
    justification: str

    def __post_init__(self) -> None:
        if self.framework not in TAXONOMY_FRAMEWORKS:
            raise ValueError(
                f"Unknown taxonomy framework '{self.framework}'. "
                f"Must be one of: {', '.join(sorted(TAXONOMY_FRAMEWORKS))}"
            )
        if not self.justification:
            raise ValueError("Taxonomy justification must not be empty.")


@dataclass
class TaxonomyMapping:
    primary: TaxonomyEntry
    secondary: list[TaxonomyEntry] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.primary.framework != "owasp_asi":
            raise ValueError("Primary taxonomy mapping must use 'owasp_asi'.")


# ---------------------------------------------------------------------------
# Severity (Contract §5)
# ---------------------------------------------------------------------------

SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")
AARF_VALUES = {0.0, 0.5, 1.0}


@dataclass
class AARFAssessment:
    autonomy: float
    tools: float
    language: float
    context: float
    non_determinism: float
    opacity: float
    persistence: float
    identity: float
    multi_agent: float
    self_modification: float

    def __post_init__(self) -> None:
        for name in (
            "autonomy", "tools", "language", "context", "non_determinism",
            "opacity", "persistence", "identity", "multi_agent", "self_modification",
        ):
            val = getattr(self, name)
            if val not in AARF_VALUES:
                raise ValueError(f"AARF factor '{name}' must be 0.0, 0.5, or 1.0, got {val}")


@dataclass
class SeverityRating:
    default: str
    cvss_base: float | None = None
    aarf: AARFAssessment | None = None

    def __post_init__(self) -> None:
        if self.default not in SEVERITY_LEVELS:
            raise ValueError(f"Severity must be one of {SEVERITY_LEVELS}, got '{self.default}'")
        if self.default != "info" and self.cvss_base is None:
            raise ValueError(f"CVSS base score is required for severity '{self.default}'.")


# ---------------------------------------------------------------------------
# Target Data (Contract §6.1)
# ---------------------------------------------------------------------------

@dataclass
class TargetConfig:
    framework: str
    config: dict
    tools: list[dict]
    mcp_servers: list[dict]
    system_prompt: str | None
    files: dict[str, str]
    metadata: dict


# ---------------------------------------------------------------------------
# Probe Target (Contract v2.0 — Wedge 2)
# ---------------------------------------------------------------------------

TRANSPORT_TYPES = ("stdio", "sse", "websocket")


@dataclass
class ProbeTarget:
    """Target for active infrastructure probing (Wedge 2)."""

    endpoint: str  # Command (stdio) or URL (sse/websocket)
    transport: str  # "stdio" | "sse" | "websocket"
    server_name: str = ""
    auth_context: dict = field(default_factory=dict)
    tls_config: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    # Link back to static config (populated when scan discovers probe targets)
    config_target: TargetConfig | None = None

    def __post_init__(self) -> None:
        if self.transport not in TRANSPORT_TYPES:
            raise ValueError(
                f"Transport must be one of {TRANSPORT_TYPES}, got '{self.transport}'"
            )


@dataclass
class ProbeResponse:
    """Response from an infrastructure probe."""

    status: str  # "success" | "error" | "timeout" | "refused"
    body: dict | str | None = None
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    transport_info: dict = field(default_factory=dict)
    error: str | None = None


class SessionContext:
    """Accumulated state across probes in a scan session.

    Provides synchronous helpers for check authors to send MCP requests
    without dealing with async transport directly.
    """

    def __init__(self) -> None:
        self.session_id: str = uuid4().hex[:12]
        self.probe_results: list[ProbeResponse] = []
        self.baseline: dict = {}
        self.canaries: dict[str, str] = {}
        self.metadata: dict = {}
        # Transport factory — set by the engine before passing to checks
        self._transport_factory: object | None = None

    def mcp_request(
        self,
        method: str,
        params: dict | None = None,
        target: ProbeTarget | None = None,
        timeout_sec: float = 10.0,
    ) -> ProbeResponse:
        """Send an MCP JSON-RPC request and return the response.

        This is a synchronous wrapper around the async transport layer.
        The engine sets up _transport_factory before handing the session to checks.
        """
        if self._transport_factory is None:
            return ProbeResponse(
                status="error", error="No transport factory configured"
            )

        from reaper.transport.factory import create_transport

        async def _do_request() -> ProbeResponse:
            transport = create_transport(target)
            start = _time.monotonic()
            try:
                await asyncio.wait_for(transport.connect(), timeout=timeout_sec)
                result = await asyncio.wait_for(
                    transport.send_request(method, params or {}),
                    timeout=timeout_sec,
                )
                elapsed = (_time.monotonic() - start) * 1000
                return ProbeResponse(
                    status="success", body=result, elapsed_ms=elapsed
                )
            except asyncio.TimeoutError:
                elapsed = (_time.monotonic() - start) * 1000
                return ProbeResponse(
                    status="timeout", elapsed_ms=elapsed, error="Request timed out"
                )
            except ConnectionRefusedError:
                elapsed = (_time.monotonic() - start) * 1000
                return ProbeResponse(
                    status="refused", elapsed_ms=elapsed, error="Connection refused"
                )
            except Exception as exc:
                elapsed = (_time.monotonic() - start) * 1000
                return ProbeResponse(
                    status="error", elapsed_ms=elapsed, error=str(exc)
                )
            finally:
                await transport.close()

        response = asyncio.run(_do_request())
        self.probe_results.append(response)
        return response


# ---------------------------------------------------------------------------
# Finding Output (Contract §6.3–6.5)
# ---------------------------------------------------------------------------

CONFIDENCE_LEVELS = ("high", "medium", "low")
EFFORT_LEVELS = ("trivial", "low", "medium", "high")


@dataclass
class Evidence:
    observable: str
    file_path: str | None
    line: int | None
    line_end: int | None
    raw_value: str
    context: dict[str, str] = field(default_factory=dict)


@dataclass
class Remediation:
    description: str
    steps: dict[str, str]
    references: list[str]
    effort: str

    def __post_init__(self) -> None:
        if self.effort not in EFFORT_LEVELS:
            raise ValueError(f"Effort must be one of {EFFORT_LEVELS}, got '{self.effort}'")


@dataclass
class Finding:
    check_id: str
    severity: str
    confidence: str
    evidence: Evidence
    remediation: Remediation
    taxonomy: TaxonomyMapping

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(f"Severity must be one of {SEVERITY_LEVELS}, got '{self.severity}'")
        if self.confidence not in CONFIDENCE_LEVELS:
            raise ValueError(
                f"Confidence must be one of {CONFIDENCE_LEVELS}, got '{self.confidence}'"
            )


# ---------------------------------------------------------------------------
# Test Fixtures (Contract §7)
# ---------------------------------------------------------------------------

FIXTURE_EXPECTATIONS = ("vulnerable", "safe", "borderline")


@dataclass
class TestFixture:
    fixture_id: str
    description: str
    expected: str
    target: TargetConfig

    def __post_init__(self) -> None:
        if self.expected not in FIXTURE_EXPECTATIONS:
            raise ValueError(
                f"Expected must be one of {FIXTURE_EXPECTATIONS}, got '{self.expected}'"
            )


# ---------------------------------------------------------------------------
# Base Check Class (Contract §8, §13)
# ---------------------------------------------------------------------------

# Valid values for check metadata
CONTRACT_VERSIONS = {"1.0", "2.0"}
CATEGORIES = ("config", "infra", "runtime")
WEDGES = (1, 2, 3)
TIERS = ("community", "pro")
CHECK_TYPES = ("deterministic", "heuristic")
CANONICAL_FRAMEWORKS = (
    "openclaw", "claude_code", "langchain", "crewai",
    "autogen", "mcp_generic", "hermes",
)


class ReaperCheck:
    """Base class for all REAPER detection checks."""

    # --- Identity (must be overridden) ---
    check_id: str = ""
    name: str = ""
    description: str = ""
    contract_version: str = "1.0"

    # --- Classification ---
    category: str = "config"
    wedge: int = 1
    tier: str = "community"
    frameworks: list[str] = []
    check_type: str = "deterministic"

    # --- Taxonomy ---
    taxonomy: TaxonomyMapping | None = None

    # --- Severity ---
    severity: SeverityRating | None = None

    def detect(self, target: TargetConfig) -> Finding | None:
        """Wedge 1: static config analysis. Subclasses must override for Wedge 1 checks."""
        raise NotImplementedError

    def probe(self, target: ProbeTarget, session: SessionContext) -> Finding | None:
        """Wedge 2: active infrastructure probing. Override for Wedge 2 checks."""
        raise NotImplementedError

    def log(self, level: str, message: str) -> None:
        """Emit a diagnostic message captured by the engine."""
        allowed = ("debug", "info", "warning", "error")
        if level not in allowed:
            level = "info"
        getattr(logger, level)(f"[{self.check_id}] {message}")

    def validate_metadata(self) -> list[str]:
        """Return a list of contract violations found in this check's metadata."""
        errors: list[str] = []
        if not self.check_id:
            errors.append("check_id is required")
        if not self.name:
            errors.append("name is required")
        if len(self.name) > 80:
            errors.append(f"name exceeds 80 chars ({len(self.name)})")
        if not self.description:
            errors.append("description is required")
        if self.contract_version not in CONTRACT_VERSIONS:
            errors.append(f"contract_version '{self.contract_version}' not in {CONTRACT_VERSIONS}")
        if self.category not in CATEGORIES:
            errors.append(f"category '{self.category}' not in {CATEGORIES}")
        if self.wedge not in WEDGES:
            errors.append(f"wedge {self.wedge} not in {WEDGES}")
        if self.tier not in TIERS:
            errors.append(f"tier '{self.tier}' not in {TIERS}")
        if self.check_type not in CHECK_TYPES:
            errors.append(f"check_type '{self.check_type}' not in {CHECK_TYPES}")
        if not self.frameworks:
            errors.append("frameworks list is empty")
        else:
            for fw in self.frameworks:
                if fw != "universal" and fw not in CANONICAL_FRAMEWORKS:
                    errors.append(f"unknown framework '{fw}'")
        if self.taxonomy is None:
            errors.append("taxonomy mapping is required")
        if self.severity is None:
            errors.append("severity rating is required")
        # Wedge 2 checks must use contract v2.0 and category "infra"
        if self.wedge == 2:
            if self.contract_version != "2.0":
                errors.append("Wedge 2 checks require contract_version '2.0'")
            if self.category != "infra":
                errors.append("Wedge 2 checks require category 'infra'")
        return errors
