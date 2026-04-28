"""Tests for reaper.models package."""

from pathlib import Path

import pytest

from reaper.models import (
    # Recon + Risk Scoring
    AgentIdentity,
    AuthMechanism,
    DataExposure,
    Guardrails,
    ReconProfile,
    RiskTier,
    ToolInventoryProfile,
    compute_blast_radius,
    compute_domain_scores,
    compute_risk_scores,
    # Catalog
    Vulnerability,
    load_aasv_bundle,
    load_owasp_categories,
    # Scan State
    CanaryRecord,
    CanaryRegistry,
    ToolChainGraph,
    ToolRecord,
    # Discovery
    InjectionFinding,
    PoisoningFinding,
    BypassFinding,
    PromptBoundaryMap,
    RetrievalSurfaceMap,
    RefusalTopology,
    PlantedDocument,
    # Classification
    ClassifiedFindingEnvelope,
    OWASP_MAPPING_MATRIX,
    SEVERITY_MATRIX,
    AUTO_ESCALATION_RULES,
    CLASS_C_THRESHOLDS,
    CONTEXTUAL_FACTORS,
    compute_base_severity,
    lookup_mapping,
)


CATALOG_DIR = Path(__file__).resolve().parent.parent / "catalogue"


# =========================================================================
# Recon Profile + Risk Scoring (#1-2)
# =========================================================================

class TestReconProfile:

    def test_default_worst_case(self):
        """Defaults should be worst-case per spec."""
        p = ReconProfile()
        assert p.agent_identity.autonomy_level == 4
        assert p.agent_identity.model_hardening == 0
        assert p.tool_inventory.tool_count == 50
        assert p.tool_inventory.write_capable_pct == 100.0
        assert p.tool_inventory.auth_mechanism == AuthMechanism.OAUTH_USER
        assert p.data_exposure.pii_in_context == 4
        assert p.data_exposure.untrusted_rag_sources == 4
        assert p.data_exposure.secrets_in_prompt is True
        assert p.guardrails.input_filter_strength == 0
        assert p.guardrails.hitl_coverage_pct == 0.0
        assert p.guardrails.instruction_hierarchy is False

    def test_resolve_field(self):
        p = ReconProfile()
        assert p.resolve_field("agent_identity.autonomy_level") == 4
        assert p.resolve_field("guardrails.instruction_hierarchy") is False
        assert p.resolve_field("nonexistent.path") is None


class TestRiskScoring:

    def test_worst_case_profile_is_critical(self):
        """Default worst-case profile should be Critical tier."""
        p = ReconProfile()
        scores = compute_risk_scores(p)
        assert scores.tier == RiskTier.CRITICAL
        assert scores.composite >= 75
        assert scores.blast_radius == 2.0

    def test_hardened_chatbot_is_low(self):
        """Hardened chatbot preset: autonomy=1, 2 tools, no RAG, strong guardrails."""
        p = ReconProfile(
            agent_identity=AgentIdentity(autonomy_level=1, model_hardening=3),
            tool_inventory=ToolInventoryProfile(
                tool_count=2, write_capable_pct=0.0,
                auth_mechanism=AuthMechanism.SERVICE_ACCOUNT,
            ),
            data_exposure=DataExposure(
                pii_in_context=0, untrusted_rag_sources=0,
                secrets_in_prompt=False,
            ),
            guardrails=Guardrails(
                input_filter_strength=3, hitl_coverage_pct=80.0,
                output_filter_strength=3, instruction_hierarchy=True,
            ),
        )
        scores = compute_risk_scores(p)
        assert scores.tier == RiskTier.LOW
        assert scores.composite <= 24

    def test_domain_scores_clamped(self):
        """Domain scores should never go below 0."""
        p = ReconProfile(
            agent_identity=AgentIdentity(autonomy_level=0, model_hardening=4),
            tool_inventory=ToolInventoryProfile(
                tool_count=0, write_capable_pct=0.0,
                auth_mechanism=AuthMechanism.NONE,
            ),
            data_exposure=DataExposure(
                pii_in_context=0, untrusted_rag_sources=0,
                secrets_in_prompt=False,
            ),
            guardrails=Guardrails(
                input_filter_strength=4, hitl_coverage_pct=100.0,
                output_filter_strength=4, instruction_hierarchy=True,
            ),
        )
        ds = compute_domain_scores(p)
        assert ds.prompt_risk >= 0
        assert ds.tool_risk >= 0
        assert ds.output_risk >= 0

    def test_blast_radius_bounds(self):
        """Blast radius must be between 1.0 and 2.0."""
        low = ReconProfile(
            agent_identity=AgentIdentity(autonomy_level=0),
            tool_inventory=ToolInventoryProfile(
                write_capable_pct=0.0,
                auth_mechanism=AuthMechanism.NONE,
            ),
            data_exposure=DataExposure(secrets_in_prompt=False),
            guardrails=Guardrails(hitl_coverage_pct=100.0),
        )
        assert compute_blast_radius(low) == 1.0

        high = ReconProfile()  # all worst-case
        assert compute_blast_radius(high) == 2.0


# =========================================================================
# Threat Catalog (#3-4)
# =========================================================================

class TestCatalog:

    def test_load_owasp_categories(self):
        seed_path = CATALOG_DIR / "owasp" / "asi-2026-seed.json"
        if not seed_path.exists():
            pytest.skip("OWASP seed file not found")
        cats = load_owasp_categories(seed_path)
        assert len(cats) == 10
        assert cats[0].owasp_id == "ASI01"
        assert cats[9].owasp_id == "ASI10"
        for cat in cats:
            assert cat.version == "ASI-2026"
            assert cat.legacy_alias.startswith("OWASP-AGENT-")

    def test_load_aasv_bundle(self):
        bundle_path = CATALOG_DIR / "aasv" / "AASV-001-complete-bundle.json"
        if not bundle_path.exists():
            pytest.skip("AASV-001 bundle not found")
        bundle = load_aasv_bundle(bundle_path)
        assert bundle.vulnerability.vuln_id == "AASV-001"
        assert bundle.vulnerability.domain == "prompt"
        assert bundle.vulnerability.owasp_category_id == "ASI01"
        assert bundle.vulnerability.status == "confirmed"
        assert len(bundle.test_cases) == 5
        assert len(bundle.payloads) == 5
        assert len(bundle.prerequisites) == 2
        assert bundle.remediation is not None
        assert bundle.remediation.remediation_id == "REM-001"

    def test_vulnerability_fields(self):
        v = Vulnerability(
            vuln_id="AASV-999",
            title="Test vuln",
            domain="prompt",
            sub_type="injection_cat1",
            owasp_category_id="ASI01",
        )
        assert v.status == "draft"
        assert v.exploitability_score == 5.0
        assert v.known_affected_frameworks == ["*"]

    def test_scan_finding_defaults(self):
        from reaper.models import ScanFinding
        f = ScanFinding(finding_id="FND-20260414-001", scan_id="s1", vuln_id="AASV-001", test_id="TC-001-01")
        assert f.status == "inconclusive"
        assert f.confidence == "low"


# =========================================================================
# Scan State (#5-11)
# =========================================================================

class TestScanState:

    def test_tool_record(self):
        t = ToolRecord(tool_id="t1", mcp_server="my-server", tool_name="read_file")
        assert t.discovery_method == "declared"
        assert t.write_capable is False

    def test_tool_chain_graph(self):
        g = ToolChainGraph(scan_id="s1")
        assert len(g.nodes) == 0
        assert len(g.edges) == 0
        assert len(g.chains) == 0

    def test_canary_registry(self):
        reg = CanaryRegistry(scan_id="s1", canaries=[
            CanaryRecord(canary_id="c1", scan_id="s1", canary_type="c1_seeded", lifecycle="active"),
            CanaryRecord(canary_id="c2", scan_id="s1", canary_type="c2_response_injected", lifecycle="generated"),
        ])
        active = reg.active_canaries()
        assert len(active) == 1
        assert active[0].canary_id == "c1"


# =========================================================================
# Discovery Findings (#12-18)
# =========================================================================

class TestDiscoveryFindings:

    def test_injection_finding_fields(self):
        f = InjectionFinding(
            finding_id="inj-001", scan_id="s1", vuln_id="AASV-001",
            test_id="TC-001-01", category="cat1", pattern="A",
            verdict="confirmed", confidence=0.95,
            canary_used="OVERRIDE SUCCESSFUL-a7f2", canary_detected=True,
        )
        assert f.category == "cat1"
        assert f.confidence == 0.95
        assert f.canary_detected is True

    def test_poisoning_finding_fields(self):
        f = PoisoningFinding(
            finding_id="poi-001", scan_id="s1",
            vector="v1", verdict="likely", confidence=0.7,
        )
        assert f.vector == "v1"

    def test_bypass_finding_fields(self):
        f = BypassFinding(
            finding_id="byp-001", scan_id="s1",
            bypass_category="b1", turns_to_compromise=5,
            verdict="confirmed", confidence=0.85,
        )
        assert f.turns_to_compromise == 5

    def test_prompt_boundary_map(self):
        pbm = PromptBoundaryMap(record_id="PBM-s1", scan_id="s1")
        assert not pbm.instruction_hierarchy_detected

    def test_retrieval_surface_map(self):
        rsm = RetrievalSurfaceMap(record_id="RSM-s1", scan_id="s1")
        assert rsm.untrusted_source_count == 0

    def test_refusal_topology(self):
        rt = RefusalTopology(record_id="RT-s1", scan_id="s1")
        assert not rt.content_policy_detected

    def test_planted_document(self):
        vdoc = PlantedDocument(record_id="VDOC-s1-001", scan_id="s1")
        assert vdoc.lifecycle == "planted"


# =========================================================================
# Classification
# =========================================================================

class TestClassification:

    def test_cfe_defaults(self):
        cfe = ClassifiedFindingEnvelope(cfe_id="CFE-s1-001", scan_id="s1")
        assert cfe.verdict == ""
        assert cfe.confidence == 0.0
        assert cfe.owasp_primary == ""
        assert cfe.dedup_group_id == ""

    def test_mapping_matrix_has_49_rows(self):
        assert len(OWASP_MAPPING_MATRIX) == 49

    def test_mapping_matrix_covers_all_layers(self):
        layers = {row.source_layer for row in OWASP_MAPPING_MATRIX}
        assert layers == {"prompt", "tool", "config", "output"}

    def test_mapping_matrix_all_rows_have_primary_asi(self):
        for row in OWASP_MAPPING_MATRIX:
            assert row.owasp_primary.startswith("ASI"), f"Row {row.row_id} missing ASI"

    def test_lookup_mapping(self):
        row = lookup_mapping("injection", "injection_cat1")
        assert row is not None
        assert row.owasp_primary == "ASI01"
        assert "CWE-74" in row.cwe_ids

        assert lookup_mapping("nonexistent", "fake") is None

    def test_severity_matrix_4x4(self):
        assert len(SEVERITY_MATRIX) == 16
        assert compute_base_severity("catastrophic", "trivial") == "critical"
        assert compute_base_severity("catastrophic", "high") == "high"
        assert compute_base_severity("minor", "high") == "info"
        assert compute_base_severity("moderate", "moderate") == "medium"

    def test_auto_escalation_rules_count(self):
        ac = [r for r in AUTO_ESCALATION_RULES if r.escalation_type == "auto_critical"]
        ah = [r for r in AUTO_ESCALATION_RULES if r.escalation_type == "auto_high"]
        assert len(ac) == 9
        assert len(ah) == 5

    def test_class_c_thresholds(self):
        assert len(CLASS_C_THRESHOLDS) == 10
        cat6 = next(t for t in CLASS_C_THRESHOLDS if t.key == "cat6_erosion")
        assert cat6.threshold_value == 3
        assert cat6.secondary_asi == "ASI09"

    def test_contextual_factors(self):
        assert len(CONTEXTUAL_FACTORS) == 9
        escalation = [f for f in CONTEXTUAL_FACTORS if f.direction == "escalation"]
        mitigation = [f for f in CONTEXTUAL_FACTORS if f.direction == "mitigation"]
        assert len(escalation) == 6
        assert len(mitigation) == 3
