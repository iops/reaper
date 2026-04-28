"""
REAPER Data Models.

Import from this package for convenience:

    from reaper.models import ReconProfile, compute_risk_scores
    from reaper.models import Vulnerability, load_owasp_categories
    from reaper.models import ClassifiedFindingEnvelope
"""

# --- Recon Profile + Risk Scoring ---
from reaper.models.recon import (
    AgentIdentity,
    AuthMechanism,
    DataExposure,
    DomainScores,
    Guardrails,
    ReconProfile,
    RiskScores,
    RiskTier,
    ScanPlan,
    ToolInventoryProfile,
    compute_blast_radius,
    compute_domain_scores,
    compute_risk_scores,
)

# --- Threat Catalog + OWASP Seed Loader ---
from reaper.models.catalog import (
    AASVBundle,
    AttackComplexity,
    AttackVector,
    CatalogRemediation,
    CrossReferences,
    FindingConfidence,
    FindingStatus,
    FixType,
    ImpactLevel as CatalogImpactLevel,
    OWASPCategory,
    Payload,
    PayloadEncoding,
    PrereqOperator,
    Prerequisite,
    RemediationDifficulty,
    ScanFinding,
    ScanMode,
    TestCase,
    Vulnerability,
    VulnDomain,
    VulnStatus,
    load_aasv_bundle,
    load_all_aasv_bundles,
    load_owasp_categories,
)

# --- Scan State Records ---
from reaper.models.scan_state import (
    CallFlowBaseline,
    CallFlowEntry,
    CanaryFormat,
    CanaryLifecycle,
    CanaryRecord,
    CanaryRegistry,
    CanaryType,
    ChainType,
    CombinationFlag,
    ConfigAuditCheck,
    ConfigAuditFinding,
    ConfigCheckSeverity,
    DataFlowEdge,
    DataFlowMap,
    DataFlowNode,
    DiscoveryMethod,
    EnforcementLayer,
    ToolAuthMechanism,
    ToolChain,
    ToolChainEdge,
    ToolChainGraph,
    ToolChainNode,
    ToolOperation,
    ToolOperationType,
    ToolRecord,
    ToolRole,
)

# --- Discovery Finding Records ---
from reaper.models.discovery import (
    BoundaryProbe,
    BypassCategory,
    BypassFinding,
    BypassMechanism,
    ExfilType,
    HijackType,
    InjectionCategory,
    InjectionFinding,
    PlantedDocument,
    PoisoningDetectionMethod,
    PoisoningFinding,
    PoisoningSourceType,
    PoisoningVector,
    PromptBoundaryMap,
    RefusalTopology,
    RefusalTrigger,
    RetrievalSource,
    RetrievalSurfaceMap,
    VDOCLifecycle,
    Verdict,
)

# --- Classification ---
from reaper.models.classification import (
    AUTO_ESCALATION_RULES,
    CLASS_C_THRESHOLDS,
    CONTEXTUAL_FACTORS,
    OWASP_MAPPING_MATRIX,
    SEVERITY_MATRIX,
    AmbiguityClass,
    AutoEscalationRule,
    CFEVerdict,
    CatalogMatch,
    ClassifiedFindingEnvelope,
    CompoundPathId,
    CompletenessState,
    ConfidenceSourceType,
    ContextualFactor,
    CrossRefType,
    CrossReference,
    EscalationType,
    EvidenceSignal,
    EvidenceSummary,
    ExploitabilityLevel,
    ImpactLevel,
    MatchType,
    OWASPMappingRow,
    SeverityLevel,
    SeverityRecord,
    SourceDomain,
    SourceLayer,
    ThresholdEntry,
    compute_base_severity,
    lookup_mapping,
)

__all__ = [
    # Recon + Risk Scoring
    "AgentIdentity", "AuthMechanism", "DataExposure", "DomainScores",
    "Guardrails", "ReconProfile", "RiskScores", "RiskTier", "ScanPlan",
    "ToolInventoryProfile", "compute_blast_radius", "compute_domain_scores",
    "compute_risk_scores",
    # Catalog
    "AASVBundle", "AttackComplexity", "AttackVector", "CatalogRemediation",
    "CrossReferences", "FindingConfidence", "FindingStatus", "FixType",
    "CatalogImpactLevel", "OWASPCategory", "Payload", "PayloadEncoding",
    "PrereqOperator", "Prerequisite", "RemediationDifficulty", "ScanFinding",
    "ScanMode", "TestCase", "Vulnerability", "VulnDomain", "VulnStatus",
    "load_aasv_bundle", "load_all_aasv_bundles", "load_owasp_categories",
    # Scan State
    "CallFlowBaseline", "CallFlowEntry", "CanaryFormat", "CanaryLifecycle",
    "CanaryRecord", "CanaryRegistry", "CanaryType", "ChainType",
    "CombinationFlag", "ConfigAuditCheck", "ConfigAuditFinding",
    "ConfigCheckSeverity", "DataFlowEdge", "DataFlowMap", "DataFlowNode",
    "DiscoveryMethod", "EnforcementLayer", "ToolAuthMechanism", "ToolChain",
    "ToolChainEdge", "ToolChainGraph", "ToolChainNode", "ToolOperation",
    "ToolOperationType", "ToolRecord", "ToolRole",
    # Discovery Findings
    "BoundaryProbe", "BypassCategory", "BypassFinding", "BypassMechanism",
    "ExfilType", "HijackType", "InjectionCategory", "InjectionFinding",
    "PlantedDocument", "PoisoningDetectionMethod", "PoisoningFinding",
    "PoisoningSourceType", "PoisoningVector", "PromptBoundaryMap",
    "RefusalTopology", "RefusalTrigger", "RetrievalSource",
    "RetrievalSurfaceMap", "VDOCLifecycle", "Verdict",
    # Classification Pipeline
    "AUTO_ESCALATION_RULES", "CLASS_C_THRESHOLDS", "CONTEXTUAL_FACTORS",
    "OWASP_MAPPING_MATRIX", "SEVERITY_MATRIX", "AmbiguityClass",
    "AutoEscalationRule", "CFEVerdict", "CatalogMatch",
    "ClassifiedFindingEnvelope", "CompoundPathId", "CompletenessState",
    "ConfidenceSourceType", "ContextualFactor", "CrossRefType",
    "CrossReference", "EscalationType", "EvidenceSignal", "EvidenceSummary",
    "ExploitabilityLevel", "ImpactLevel", "MatchType", "OWASPMappingRow",
    "SeverityLevel", "SeverityRecord", "SourceDomain", "SourceLayer",
    "ThresholdEntry", "compute_base_severity", "lookup_mapping",
]
