"""
Data Models — Scan State Records.

These models track the evolving state of a single scan session —
tool inventory, chain graphs, call flow baselines, canaries, data flows,
and config audit results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class DiscoveryMethod(str, Enum):
    DECLARED = "declared"
    PROBED = "probed"
    SHADOW = "shadow"
    CONFIG_AUDIT = "config_audit"


class ToolAuthMechanism(str, Enum):
    NONE = "none"
    API_KEY_STATIC = "api_key_static"
    SERVICE_ACCOUNT = "service_account"
    OAUTH_USER = "oauth_user"


class ToolOperationType(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"


class ToolRole(str, Enum):
    SOURCE = "source"
    SINK = "sink"
    RELAY = "relay"
    SOURCE_SINK = "source_sink"


class ChainType(str, Enum):
    EXFIL = "exfil"
    ESCALATION = "escalation"
    LATERAL = "lateral"
    POISONING = "poisoning"


class CanaryFormat(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    API_KEY = "api_key"
    NAME = "name"
    CREDIT_CARD = "credit_card"
    ADDRESS = "address"


class CanaryType(str, Enum):
    C1_SEEDED = "c1_seeded"
    C2_RESPONSE_INJECTED = "c2_response_injected"
    C3_CONTEXT = "c3_context"
    C4_PARAMETER = "c4_parameter"
    C5_COMPOSITE = "c5_composite"


class CanaryLifecycle(str, Enum):
    GENERATED = "generated"
    PLANTED = "planted"
    ACTIVE = "active"
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    CLEANUP_PENDING = "cleanup_pending"
    CLEANED = "cleaned"


class EnforcementLayer(str, Enum):
    NONE = "none"
    AGENT_ONLY = "agent_only"
    SERVER_ENFORCED = "server_enforced"
    BOTH = "both"


class ConfigCheckSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CombinationFlag(str, Enum):
    SECURITY_THEATER = "security_theater"
    ARCHITECTURAL_VULNERABILITY = "architectural_vulnerability"
    SEVERITY_MULTIPLIER = "severity_multiplier"
    FOUNDATION_MISSING = "foundation_missing"
    DEFENSE_THEATER = "defense_theater"


# ---------------------------------------------------------------------------
# Item #5: Tool Inventory Record (18 fields)
# ---------------------------------------------------------------------------

@dataclass
class ToolOperation:
    """A single operation a tool can perform."""
    type: str  # ToolOperationType value


@dataclass
class ToolRecord:
    """Discovered tool from passive enumeration (P1-P6) or config audit."""
    tool_id: str
    mcp_server: str = ""
    tool_name: str = ""
    description: str = ""
    discovery_method: str = "declared"     # DiscoveryMethod value
    capability_domain: str = ""            # filesystem, database, email, etc.
    operations: list[ToolOperation] = field(default_factory=list)
    auth_mechanism: str = "none"           # ToolAuthMechanism value
    scope_declared: str = ""
    scope_actual: str = ""
    hitl_required: bool = False
    hitl_verified: bool = False
    rate_limited: bool = False
    write_capable: bool = False
    data_access_scope: str = ""
    chain_inputs: list[str] = field(default_factory=list)
    chain_outputs: list[str] = field(default_factory=list)
    risk_notes: str = ""


# ---------------------------------------------------------------------------
# Item #6: Tool Chain Graph
# ---------------------------------------------------------------------------

@dataclass
class ToolChainNode:
    """A node in the tool chain graph."""
    tool_id: str
    role: str = "relay"        # ToolRole value
    sensitivity: str = ""


@dataclass
class ToolChainEdge:
    """An edge in the tool chain graph (data flow between tools)."""
    source_tool_id: str
    target_tool_id: str
    data_type: str = ""        # what flows between them
    compatible: bool = True


@dataclass
class ToolChain:
    """A pre-computed chain with risk assessment."""
    chain_id: str
    chain_type: str            # ChainType value
    tool_ids: list[str] = field(default_factory=list)
    risk_score: float = 0.0    # source_sensitivity x sink_capability x path x auth


@dataclass
class ToolChainGraph:
    """Complete tool chain graph for a scan. Item #6."""
    scan_id: str
    nodes: list[ToolChainNode] = field(default_factory=list)
    edges: list[ToolChainEdge] = field(default_factory=list)
    chains: list[ToolChain] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Item #7: Call Flow Baseline Record
# ---------------------------------------------------------------------------

@dataclass
class CallFlowEntry:
    """A single observed call pattern from baseline profiling."""
    task_description: str
    tool_called: str
    parameters: dict[str, Any] = field(default_factory=dict)
    sequence_position: int = 0
    is_bonus_call: bool = False  # call not strictly required by task


@dataclass
class CallFlowBaseline:
    """Baseline call flow record from passive mode O1-O6. Item #7."""
    scan_id: str
    entries: list[CallFlowEntry] = field(default_factory=list)
    tool_preferences: dict[str, str] = field(default_factory=dict)
    hitl_coverage: dict[str, bool] = field(default_factory=dict)
    refusal_surface: list[str] = field(default_factory=list)
    fallback_routing: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Item #8: Canary Registry
# ---------------------------------------------------------------------------

@dataclass
class CanaryRecord:
    """A single canary token in the registry. Item #8."""
    canary_id: str
    scan_id: str
    canary_type: str               # CanaryType value
    format: str = ""               # CanaryFormat value (for C1)
    generated_value: str = ""
    detection_pattern: str = ""    # regex or exact match
    planted_location: str = ""
    lifecycle: str = "generated"   # CanaryLifecycle value
    strategy: str = ""             # C2 strategy A-E
    context_source: str = ""       # C3 vector
    relay_chain: str = ""          # C4 chain reference
    scatter_mode: str = ""         # C5: co_located/distributed/mixed
    identity_fields: list[str] = field(default_factory=list)  # C5 fields
    detected_in: str = ""          # where canary was found if detected
    detected_at: str = ""          # ISO8601 timestamp


@dataclass
class CanaryRegistry:
    """Collection of all canaries for a scan session."""
    scan_id: str
    canaries: list[CanaryRecord] = field(default_factory=list)

    def active_canaries(self) -> list[CanaryRecord]:
        return [c for c in self.canaries if c.lifecycle == CanaryLifecycle.ACTIVE.value]


# ---------------------------------------------------------------------------
# Item #9: Data Flow Map
# ---------------------------------------------------------------------------

@dataclass
class DataFlowNode:
    """A node in the data flow map — a data store or channel."""
    node_id: str
    node_type: str = ""       # data_store, channel, tool, context
    sensitivity: str = ""
    contains_pii: bool = False
    contains_secrets: bool = False


@dataclass
class DataFlowEdge:
    """An observed data flow between nodes."""
    source_id: str
    target_id: str
    data_type: str = ""
    direction: str = "outbound"   # inbound, outbound, bidirectional
    redacted: bool = False


@dataclass
class DataFlowMap:
    """Data flow map from passive mode D1-D5. Item #9."""
    scan_id: str
    nodes: list[DataFlowNode] = field(default_factory=list)
    edges: list[DataFlowEdge] = field(default_factory=list)
    sensitive_locations: list[str] = field(default_factory=list)   # D1 output
    outbound_channels: list[str] = field(default_factory=list)     # D2 output
    redaction_baseline: dict[str, bool] = field(default_factory=dict)  # D5 output


# ---------------------------------------------------------------------------
# Item #10: Config Audit Check Definitions
# ---------------------------------------------------------------------------

@dataclass
class ConfigAuditCheck:
    """Definition of a single config audit check (48 checks, D1-D7). Item #10."""
    check_id: str               # D1-01 through D7-06
    domain: str                 # D1-D7 domain name
    title: str = ""
    severity: str = "medium"    # ConfigCheckSeverity value
    description: str = ""
    test_logic: str = ""        # what the check tests
    exfil_mapping: str = ""     # X3-A through X3-F if applicable
    fuzzing_mapping: str = ""   # S1-S5, F1 if applicable


# ---------------------------------------------------------------------------
# Item #11: Config Audit Finding Record
# ---------------------------------------------------------------------------

@dataclass
class ConfigAuditFinding:
    """Result of a config audit check. Item #11."""
    finding_id: str
    scan_id: str
    check_id: str               # FK -> ConfigAuditCheck.check_id
    status: str = "not_vulnerable"  # pass/fail/not_applicable
    severity: str = "info"
    evidence: dict[str, Any] = field(default_factory=dict)
    raw_value: str = ""
    expected_value: str = ""
    combination_flags: list[str] = field(default_factory=list)  # CombinationFlag values
    remediation_hint: str = ""
