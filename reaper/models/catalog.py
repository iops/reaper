"""
Data Models — Threat Catalog.

Seven entities: OWASPCategory, Vulnerability, TestCase, Payload, Prerequisite,
CatalogRemediation, ScanFinding. Storage-agnostic — works as JSON files,
SQLite, or Postgres.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class VulnDomain(str, Enum):
    PROMPT = "prompt"
    TOOL = "tool"
    OUTPUT = "output"
    CONFIG = "config"


class VulnStatus(str, Enum):
    DRAFT = "draft"
    CONFIRMED = "confirmed"
    DEPRECATED = "deprecated"


class AttackVector(str, Enum):
    USER_INPUT = "user_input"
    TOOL_RESPONSE = "tool_response"
    RAG_CONTENT = "rag_content"
    SYSTEM_PROMPT = "system_prompt"
    INTER_AGENT = "inter_agent"
    MCP_CONFIG = "mcp_config"
    NETWORK = "network"
    LOCAL = "local"
    PHYSICAL = "physical"


class AttackComplexity(str, Enum):
    LOW = "low"
    HIGH = "high"


class ImpactLevel(str, Enum):
    HIGH = "high"
    LOW = "low"
    NONE = "none"


class ScanMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    FUZZING = "fuzzing"


class PayloadEncoding(str, Enum):
    PLAINTEXT = "plaintext"
    BASE64 = "base64"
    UNICODE_ESCAPE = "unicode_escape"
    ROT13 = "rot13"
    LEETSPEAK = "leetspeak"
    MARKDOWN_HIDDEN = "markdown_hidden"
    HTML_COMMENT = "html_comment"
    JSON_NESTED = "json_nested"
    HTML_ENTITY = "html_entity"
    UNICODE = "unicode"


class PrereqOperator(str, Enum):
    EQ = "eq"
    NEQ = "neq"
    GT = "gt"
    LT = "lt"
    GTE = "gte"
    LTE = "lte"
    CONTAINS = "contains"
    MATCHES = "matches"


class FixType(str, Enum):
    CONFIG_CHANGE = "config_change"
    CODE_PATCH = "code_patch"
    ARCHITECTURE_CHANGE = "architecture_change"
    DEFENSE_IN_DEPTH = "defense_in_depth"
    ACCEPT_RISK = "accept_risk"
    SINGLE_CONTROL = "single_control"
    CONFIGURATION = "configuration"
    ARCHITECTURAL_FIX = "architectural_fix"


class RemediationDifficulty(str, Enum):
    TRIVIAL = "trivial"
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    VERY_HARD = "very_hard"


class FindingStatus(str, Enum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    PARTIAL = "partial"
    ERROR = "error"
    INCONCLUSIVE = "inconclusive"


class FindingConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# OWASP Category (seed data entity)
# ---------------------------------------------------------------------------

@dataclass
class OWASPCategory:
    """OWASP ASI 2026 category record. FK target for Vulnerability.owasp_category_id."""
    owasp_id: str             # ASI01-ASI10
    name: str
    description: str
    cwe_ids: list[str] = field(default_factory=list)
    rank: int = 0
    version: str = "ASI-2026"
    url: str = ""
    scan_domains: list[str] = field(default_factory=list)
    legacy_alias: str = ""    # OWASP-AGENT-NN backward compat


# ---------------------------------------------------------------------------
# Vulnerability (AASV record — core catalog entity)
# ---------------------------------------------------------------------------

@dataclass
class Vulnerability:
    """AI Agent Security Vulnerability record. One per known vulnerability class."""
    vuln_id: str                     # AASV-NNN
    title: str
    domain: str                      # VulnDomain value
    sub_type: str                    # dedup merge key vocabulary
    owasp_category_id: str           # FK -> OWASPCategory.owasp_id
    cwe_ids: list[str] = field(default_factory=list)
    severity: str = "medium"         # critical/high/medium/low/info
    description: str = ""
    attack_vector: str = "user_input"
    attack_complexity: str = "low"
    impact_confidentiality: str = "low"
    impact_integrity: str = "low"
    impact_availability: str = "none"
    exploitability_score: float = 5.0  # 0-10
    known_affected_frameworks: list[str] = field(default_factory=lambda: ["*"])
    known_affected_models: list[str] = field(default_factory=lambda: ["*"])
    framework_specific_notes: dict[str, str] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    status: str = "draft"            # VulnStatus value
    source_cfe_id: str | None = None  # provenance from novel finding
    created_at: str = ""
    updated_at: str = ""


# ---------------------------------------------------------------------------
# Test Case
# ---------------------------------------------------------------------------

@dataclass
class TestCase:
    """A specific test against a target agent for a vulnerability."""
    test_id: str               # TC-VVV-NN
    vuln_id: str               # FK -> Vulnerability.vuln_id
    title: str = ""
    scan_mode: str = "active"  # ScanMode value
    priority_tier: int = 2     # 1=passive recon, 2=active targeted, 3=escalation, 4=fuzzing
    target_interface: str = "chat_input"
    estimated_duration_sec: int = 30
    requires_multi_turn: bool = False
    success_criteria: str = ""
    false_positive_notes: str = ""
    created_at: str = ""


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------

@dataclass
class Payload:
    """The actual content sent during a test. One test case -> many payloads."""
    payload_id: str              # PL-VVV-TT-X
    test_id: str                 # FK -> TestCase.test_id
    payload_type: str = "text_injection"
    content: str = ""
    target_model: str = "*"
    encoding: str = "plaintext"  # PayloadEncoding value
    language: str = "en"
    mutation_parent: str | None = None  # FK -> Payload.payload_id (self-ref)
    effectiveness_score: float = 0.5    # 0-1, updated by feedback loop
    notes: str = ""


# ---------------------------------------------------------------------------
# Prerequisite
# ---------------------------------------------------------------------------

@dataclass
class Prerequisite:
    """Recon profile condition that gates test inclusion. AND logic across all prereqs."""
    prereq_id: str       # PRQ-VVV-NN
    vuln_id: str         # FK -> Vulnerability.vuln_id
    field: str           # dot-notation path into ReconProfile
    operator: str        # PrereqOperator value
    value: Any = None
    description: str = ""


# ---------------------------------------------------------------------------
# Remediation (catalog version — distinct from sdk.Remediation)
# ---------------------------------------------------------------------------

@dataclass
class CatalogRemediation:
    """Fix instructions for a vulnerability. One per vulnerability."""
    remediation_id: str           # REM-NNN
    vuln_id: str                  # FK -> Vulnerability.vuln_id
    fix_type: str = "defense_in_depth"
    summary: str = ""
    instructions: str = ""
    validation_query: str = ""
    difficulty: str = "medium"    # RemediationDifficulty value
    estimated_effort_hours: int = 4
    framework_specific: dict[str, str] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    created_at: str = ""


# ---------------------------------------------------------------------------
# Scan Finding (instance of a vulnerability in a specific scan)
# ---------------------------------------------------------------------------

@dataclass
class ScanFinding:
    """Instance of a vulnerability detected in a target agent during a scan."""
    finding_id: str              # FND-DATE-NNN
    scan_id: str
    vuln_id: str                 # FK -> Vulnerability.vuln_id
    test_id: str                 # FK -> TestCase.test_id
    status: str = "inconclusive"  # FindingStatus value
    confidence: str = "low"       # FindingConfidence value
    evidence: dict[str, Any] = field(default_factory=dict)
    payload_id: str | None = None
    created_at: str = ""


# ---------------------------------------------------------------------------
# Cross References (bundle metadata)
# ---------------------------------------------------------------------------

@dataclass
class CrossReferences:
    """Cross-reference metadata from AASV bundles."""
    defense_topology_position: str = ""
    downstream_test_gating: dict[str, str] = field(default_factory=dict)
    dedup_behavior: str = ""
    compound_path_role: str = ""


# ---------------------------------------------------------------------------
# Complete AASV Bundle (the JSON file unit)
# ---------------------------------------------------------------------------

@dataclass
class AASVBundle:
    """A complete AASV bundle as stored in the AASV catalog."""
    vulnerability: Vulnerability
    test_cases: list[TestCase] = field(default_factory=list)
    payloads: list[Payload] = field(default_factory=list)
    prerequisites: list[Prerequisite] = field(default_factory=list)
    remediation: CatalogRemediation | None = None
    cross_references: CrossReferences = field(default_factory=CrossReferences)


# ---------------------------------------------------------------------------
# OWASP Seed Data Loader (Item #4)
# ---------------------------------------------------------------------------

def load_owasp_categories(seed_path: str | Path) -> list[OWASPCategory]:
    """Load OWASP ASI 2026 seed data from JSON.

    Args:
        seed_path: Path to asi-2026-seed.json.

    Returns:
        List of 10 OWASPCategory records (ASI01-ASI10).
    """
    path = Path(seed_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    categories = []
    for cat in data["categories"]:
        categories.append(OWASPCategory(
            owasp_id=cat["owasp_id"],
            name=cat["name"],
            description=cat["description"],
            cwe_ids=cat.get("cwe_ids", []),
            rank=cat.get("rank", 0),
            version=cat.get("version", "ASI-2026"),
            url=cat.get("url", ""),
            scan_domains=cat.get("scan_domains", []),
            legacy_alias=cat.get("legacy_alias", ""),
        ))
    return categories


def load_aasv_bundle(bundle_path: str | Path) -> AASVBundle:
    """Load a single AASV bundle from its JSON file.

    Args:
        bundle_path: Path to AASV-NNN-complete-bundle.json.

    Returns:
        Parsed AASVBundle with all sub-entities.
    """
    path = Path(bundle_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    v = data["vulnerability"]
    vuln = Vulnerability(
        vuln_id=v["vuln_id"],
        title=v["title"],
        domain=v["domain"],
        sub_type=v["sub_type"],
        owasp_category_id=v["owasp_category_id"],
        cwe_ids=v.get("cwe_ids", []),
        severity=v.get("severity", "medium"),
        description=v.get("description", ""),
        attack_vector=v.get("attack_vector", "user_input"),
        attack_complexity=v.get("attack_complexity", "low"),
        impact_confidentiality=v.get("impact_confidentiality", "low"),
        impact_integrity=v.get("impact_integrity", "low"),
        impact_availability=v.get("impact_availability", "none"),
        exploitability_score=v.get("exploitability_score", 5.0),
        known_affected_frameworks=v.get("known_affected_frameworks", ["*"]),
        known_affected_models=v.get("known_affected_models", ["*"]),
        framework_specific_notes=v.get("framework_specific_notes", {}),
        references=v.get("references", []),
        tags=v.get("tags", []),
        status=v.get("status", "draft"),
        source_cfe_id=v.get("source_cfe_id"),
        created_at=v.get("created_at", ""),
        updated_at=v.get("updated_at", ""),
    )

    test_cases = [
        TestCase(
            test_id=tc["test_id"],
            vuln_id=tc["vuln_id"],
            title=tc.get("title", ""),
            scan_mode=tc.get("scan_mode", "active"),
            priority_tier=tc.get("priority_tier", 2),
            target_interface=tc.get("target_interface", "chat_input"),
            estimated_duration_sec=tc.get("estimated_duration_sec", 30),
            requires_multi_turn=tc.get("requires_multi_turn", False),
            success_criteria=tc.get("success_criteria", ""),
            false_positive_notes=tc.get("false_positive_notes", ""),
            created_at=tc.get("created_at", ""),
        )
        for tc in data.get("test_cases", [])
    ]

    payloads = [
        Payload(
            payload_id=pl["payload_id"],
            test_id=pl["test_id"],
            payload_type=pl.get("payload_type", "text_injection"),
            content=pl.get("content", ""),
            target_model=pl.get("target_model", "*"),
            encoding=pl.get("encoding", "plaintext"),
            language=pl.get("language", "en"),
            mutation_parent=pl.get("mutation_parent"),
            effectiveness_score=pl.get("effectiveness_score", 0.5),
            notes=pl.get("notes", ""),
        )
        for pl in data.get("payloads", [])
    ]

    prerequisites = [
        Prerequisite(
            prereq_id=pr["prereq_id"],
            vuln_id=pr["vuln_id"],
            field=pr["field"],
            operator=pr["operator"],
            value=pr.get("value"),
            description=pr.get("description", ""),
        )
        for pr in data.get("prerequisites", [])
    ]

    rem_data = data.get("remediation")
    remediation = None
    if rem_data:
        remediation = CatalogRemediation(
            remediation_id=rem_data["remediation_id"],
            vuln_id=rem_data["vuln_id"],
            fix_type=rem_data.get("fix_type", "defense_in_depth"),
            summary=rem_data.get("summary", ""),
            instructions=rem_data.get("instructions", ""),
            validation_query=rem_data.get("validation_query", ""),
            difficulty=rem_data.get("difficulty", "medium"),
            estimated_effort_hours=rem_data.get("estimated_effort_hours", 4),
            framework_specific=rem_data.get("framework_specific", {}),
            references=rem_data.get("references", []),
            created_at=rem_data.get("created_at", ""),
        )

    xref_data = data.get("_cross_references", {})
    cross_refs = CrossReferences(
        defense_topology_position=xref_data.get("defense_topology_position", ""),
        downstream_test_gating=xref_data.get("downstream_test_gating", {}),
        dedup_behavior=xref_data.get("dedup_behavior", ""),
        compound_path_role=xref_data.get("compound_path_role", ""),
    )

    return AASVBundle(
        vulnerability=vuln,
        test_cases=test_cases,
        payloads=payloads,
        prerequisites=prerequisites,
        remediation=remediation,
        cross_references=cross_refs,
    )


def load_all_aasv_bundles(catalog_dir: str | Path) -> list[AASVBundle]:
    """Load all AASV bundles from a the AASV catalog directory.

    Args:
        catalog_dir: Path to the aasv/ directory containing bundle JSON files.

    Returns:
        List of AASVBundle instances, sorted by vuln_id.
    """
    path = Path(catalog_dir)
    bundles = []
    for bundle_file in sorted(path.glob("AASV-*-complete-bundle.json")):
        bundles.append(load_aasv_bundle(bundle_file))
    return bundles
