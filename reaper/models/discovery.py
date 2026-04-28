"""
Data Models — Discovery Finding Records.

Per-scan passive mapping records and domain-specific finding schemas
that the discovery stage produces and classification consumes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    INCONCLUSIVE = "inconclusive"
    NOT_VULNERABLE = "not_vulnerable"
    PARTIAL = "partial"
    FALSE_POSITIVE = "false_positive"
    ERROR = "error"


class InjectionCategory(str, Enum):
    CAT1 = "cat1"
    CAT2 = "cat2"
    CAT3 = "cat3"
    CAT4 = "cat4"
    CAT5 = "cat5"
    CAT6 = "cat6"


class PoisoningVector(str, Enum):
    V1 = "v1"
    V2 = "v2"
    V3 = "v3"
    V4 = "v4"


class PoisoningSourceType(str, Enum):
    RAG_DOCUMENT = "rag_document"
    TOOL_RESPONSE = "tool_response"
    CONVERSATION_HISTORY = "conversation_history"
    CROSS_SOURCE = "cross_source"


class PoisoningDetectionMethod(str, Enum):
    PAIRED_EXECUTION = "paired_execution"
    BEHAVIORAL_DIFF = "behavioral_diff"
    OUTPUT_ANALYSIS = "output_analysis"


class BypassCategory(str, Enum):
    B1 = "b1"
    B2 = "b2"
    B3 = "b3"
    B4 = "b4"
    B5 = "b5"


class BypassMechanism(str, Enum):
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    ENCODING_EVASION = "encoding_evasion"
    HYPOTHETICAL_FRAMING = "hypothetical_framing"
    FORMAT_MANIPULATION = "format_manipulation"
    AUTHORITY_ESCALATION = "authority_escalation"


class HijackType(str, Enum):
    H1 = "h1"
    H2 = "h2"
    H3 = "h3"


class ExfilType(str, Enum):
    X1 = "x1"
    X2 = "x2"
    X3 = "x3"
    X4 = "x4"


class VDOCLifecycle(str, Enum):
    PLANTED = "planted"
    ACTIVE = "active"
    RETRIEVED = "retrieved"
    CLEANUP_PENDING = "cleanup_pending"
    CLEANED = "cleaned"


# ---------------------------------------------------------------------------
# Item #12: Prompt Boundary Map (PBM)
# ---------------------------------------------------------------------------

@dataclass
class BoundaryProbe:
    """A single probe result from passive boundary mapping P1-P5."""
    probe_id: str
    technique: str           # P1-P5
    description: str = ""
    result: str = ""         # what was observed
    boundary_type: str = ""  # system/user, instruction/data, etc.
    strength: str = ""       # strong, weak, absent


@dataclass
class PromptBoundaryMap:
    """Passive prompt boundary mapping record. PBM-{scan_id}. Item #12."""
    record_id: str           # PBM-{scan_id}
    scan_id: str
    probes: list[BoundaryProbe] = field(default_factory=list)
    instruction_hierarchy_detected: bool = False
    delimiter_patterns: list[str] = field(default_factory=list)
    identity_anchoring_strength: str = ""  # strong, weak, absent
    refusal_triggers: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Item #13: Retrieval Surface Map (RSM)
# ---------------------------------------------------------------------------

@dataclass
class RetrievalSource:
    """A single retrieval source discovered during R1-R6 mapping."""
    source_id: str
    source_type: str = ""     # rag, tool_response, memory, web_search
    attacker_influenceable: bool = False
    content_format: str = ""  # text, json, html, markdown
    injection_surface: str = ""  # where injected content would land


@dataclass
class RetrievalSurfaceMap:
    """Passive retrieval surface mapping record. RSM-{scan_id}. Item #13."""
    record_id: str           # RSM-{scan_id}
    scan_id: str
    sources: list[RetrievalSource] = field(default_factory=list)
    untrusted_source_count: int = 0
    content_mixing_detected: bool = False
    embedding_strategy: str = ""  # how retrieved content enters context


# ---------------------------------------------------------------------------
# Item #14: Refusal Topology (RT)
# ---------------------------------------------------------------------------

@dataclass
class RefusalTrigger:
    """A single refusal behavior observed during G1-G3 mapping."""
    trigger_id: str
    trigger_type: str = ""     # content_category, action_type, keyword
    description: str = ""
    refusal_consistency: float = 0.0  # 0-1, how reliably it refuses
    bypass_susceptibility: str = ""   # high, medium, low


@dataclass
class RefusalTopology:
    """Passive refusal topology mapping record. RT-{scan_id}. Item #14."""
    record_id: str            # RT-{scan_id}
    scan_id: str
    triggers: list[RefusalTrigger] = field(default_factory=list)
    overall_refusal_strength: str = ""  # strong, moderate, weak, absent
    content_policy_detected: bool = False
    action_policy_detected: bool = False


# ---------------------------------------------------------------------------
# Item #15: Injection Finding Record (16 fields)
# ---------------------------------------------------------------------------

@dataclass
class InjectionFinding:
    """Stage 1 injection finding from Cat 1-6 tests. Item #15."""
    finding_id: str
    scan_id: str
    vuln_id: str                 # FK -> AASV record
    test_id: str                 # FK -> test case
    category: str                # InjectionCategory value (cat1-cat6)
    pattern: str = ""            # A-E within category
    verdict: str = "inconclusive"   # Verdict value
    confidence: float = 0.0      # 0-1
    payload_id: str = ""         # FK -> payload used
    canary_used: str = ""        # canary phrase with hex suffix
    canary_detected: bool = False
    behavioral_evidence: str = ""  # agent response text
    false_positive_risk: str = ""  # FP-1 through FP-5
    defense_profile_indicator: str = ""  # Profile 1-5
    evidence_sources: list[str] = field(default_factory=list)  # E1-E4 types
    severity_preliminary: str = "medium"  # before contextual adjustment


# ---------------------------------------------------------------------------
# Item #16: Poisoning Finding Record (12 fields)
# ---------------------------------------------------------------------------

@dataclass
class PoisoningFinding:
    """Stage 1 poisoning finding from V1-V4 tests. Item #16."""
    finding_id: str
    scan_id: str
    vector: str                  # PoisoningVector value (v1-v4)
    attack_type: str = ""        # visible_embedding, invisible_text, etc.
    concealment_technique: str = ""
    verdict: str = "inconclusive"  # Verdict value
    confidence: float = 0.0
    source_type: str = ""        # PoisoningSourceType value
    detection_method: str = ""   # PoisoningDetectionMethod value
    prerequisite_satisfied: bool = False
    false_positive_risk: str = ""
    defense_profile: str = ""    # Profile 1-6


# ---------------------------------------------------------------------------
# Item #17: Bypass Finding Record (11 fields)
# ---------------------------------------------------------------------------

@dataclass
class BypassFinding:
    """Stage 1 bypass finding from B1-B5 tests. Item #17."""
    finding_id: str
    scan_id: str
    bypass_category: str         # BypassCategory value (b1-b5)
    mechanism: str = ""          # BypassMechanism value
    verdict: str = "inconclusive"  # Verdict value
    confidence: float = 0.0
    turns_to_compromise: int = 0   # for B1: multi-turn count
    reframing_method: str = ""     # B3-B4 specific
    evaluator_mode: str = ""       # 3_input, 4_input, multi_turn
    false_positive_risk: str = ""
    defense_profile: str = ""      # Profile 1-5


# ---------------------------------------------------------------------------
# Item #18: Planted Document Record (VDOC)
# ---------------------------------------------------------------------------

@dataclass
class PlantedDocument:
    """V1 planted document record. VDOC-{scan_id}-{seq}. Item #18."""
    record_id: str               # VDOC-{scan_id}-{seq}
    scan_id: str
    document_type: str = ""      # rag_document, tool_config, memory_entry
    content: str = ""            # planted content
    planted_location: str = ""   # where in the target's data stores
    injection_payload: str = ""  # the adversarial content embedded
    canary_ids: list[str] = field(default_factory=list)  # associated canary IDs
    lifecycle: str = "planted"   # VDOCLifecycle value
    planted_at: str = ""         # ISO8601
    cleaned_at: str = ""         # ISO8601
