"""Scan API — create scans, compute risk scores, execute checks."""

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException

from reaper.engine import ScannerEngine
from reaper.models import (
    AgentIdentity,
    AuthMechanism,
    DataExposure,
    Guardrails,
    ReconProfile,
    ToolInventoryProfile,
    compute_risk_scores,
)
from reaper.sdk import TargetConfig
from api import db
from api.schemas.scan import (
    ScanCreateRequest,
    ScanResponse,
    RiskScoresResponse,
    DomainScoresResponse,
    FindingResponse,
    EvidenceResponse,
    FindingRemediationResponse,
    TaxonomyEntryResponse,
)

router = APIRouter(prefix="/api/scans", tags=["scans"])

# Engine singleton — loads checks once at import time.
_CHECKS_DIR = Path(__file__).resolve().parent.parent.parent / "checks"
_engine = ScannerEngine(_CHECKS_DIR)
_engine.load_checks()


def _build_profile(req: ScanCreateRequest) -> ReconProfile:
    ai = req.agent_identity
    ti = req.tool_inventory
    de = req.data_exposure
    gr = req.guardrails
    return ReconProfile(
        agent_identity=AgentIdentity(
            autonomy_level=ai.autonomy_level,
            model_hardening=ai.model_hardening,
            framework=ai.framework,
            model_provider=ai.model_provider,
        ),
        tool_inventory=ToolInventoryProfile(
            tool_count=ti.tool_count,
            write_capable_pct=ti.write_capable_pct,
            auth_mechanism=AuthMechanism(ti.auth_mechanism),
            mcp_servers=ti.mcp_servers,
        ),
        data_exposure=DataExposure(
            pii_in_context=de.pii_in_context,
            untrusted_rag_sources=de.untrusted_rag_sources,
            data_stores_accessible=de.data_stores_accessible,
            secrets_in_prompt=de.secrets_in_prompt,
        ),
        guardrails=Guardrails(
            input_filter_strength=gr.input_filter_strength,
            hitl_coverage_pct=gr.hitl_coverage_pct,
            output_filter_strength=gr.output_filter_strength,
            instruction_hierarchy=gr.instruction_hierarchy,
        ),
    )


def _scores_to_response(scores) -> RiskScoresResponse:
    return RiskScoresResponse(
        domain_scores=DomainScoresResponse(
            prompt_risk=scores.domain_scores.prompt_risk,
            tool_risk=scores.domain_scores.tool_risk,
            output_risk=scores.domain_scores.output_risk,
        ),
        blast_radius=scores.blast_radius,
        composite=scores.composite,
        tier=scores.tier.value,
    )


def _finding_to_response(f) -> FindingResponse:
    """Convert an sdk.Finding to a FindingResponse."""
    return FindingResponse(
        check_id=f.check_id,
        severity=f.severity,
        confidence=f.confidence,
        evidence=EvidenceResponse(
            observable=f.evidence.observable,
            file_path=f.evidence.file_path,
            line=f.evidence.line,
            line_end=f.evidence.line_end,
            raw_value=f.evidence.raw_value,
            context=f.evidence.context,
        ),
        remediation=FindingRemediationResponse(
            description=f.remediation.description,
            steps=f.remediation.steps,
            references=f.remediation.references,
            effort=f.remediation.effort,
        ),
        taxonomy_primary=TaxonomyEntryResponse(
            framework=f.taxonomy.primary.framework,
            entry_id=f.taxonomy.primary.entry_id,
            justification=f.taxonomy.primary.justification,
        ),
        taxonomy_secondary=[
            TaxonomyEntryResponse(
                framework=s.framework,
                entry_id=s.entry_id,
                justification=s.justification,
            )
            for s in f.taxonomy.secondary
        ],
    )


def _build_target(target_input) -> TargetConfig:
    """Convert a TargetConfigInput to an sdk.TargetConfig."""
    return TargetConfig(
        framework=target_input.framework,
        config=target_input.config,
        tools=target_input.tools,
        mcp_servers=[s.model_dump() for s in target_input.mcp_servers],
        system_prompt=target_input.system_prompt,
        files=target_input.files,
        metadata={},
    )


@router.post("", response_model=ScanResponse)
def create_scan(req: ScanCreateRequest):
    """Create a new scan, compute risk scores, and optionally execute checks."""
    scan_id = f"scan-{uuid4().hex[:8]}"
    profile = _build_profile(req)
    profile.scan_id = scan_id
    scores = compute_risk_scores(profile)
    created_at = datetime.now(timezone.utc).isoformat()

    findings = []
    status = "completed"
    completed_at = created_at
    checks_executed = 0
    checks_skipped = 0
    duration_ms = 0.0
    errors: list[str] = []
    framework = req.agent_identity.framework

    if req.target:
        target = _build_target(req.target)
        framework = req.target.framework
        result = _engine.scan(target)
        findings = result.findings
        checks_executed = result.checks_executed
        checks_skipped = result.checks_skipped
        duration_ms = result.duration_ms
        errors = result.errors

    conn = db.get_connection()
    try:
        db.insert_scan(
            conn, scan_id, req.name, status, framework,
            {
                "prompt_risk": scores.domain_scores.prompt_risk,
                "tool_risk": scores.domain_scores.tool_risk,
                "output_risk": scores.domain_scores.output_risk,
                "blast_radius": scores.blast_radius,
                "composite": scores.composite,
                "tier": scores.tier.value,
            },
            checks_executed, checks_skipped, duration_ms,
            req.model_dump(exclude={"target"}),
            req.target.model_dump() if req.target else None,
            created_at, completed_at, errors,
        )
        for f in findings:
            db.insert_finding(conn, scan_id, f)
        conn.commit()
    finally:
        conn.close()

    severity_counts = {f.severity: 0 for f in findings}
    for f in findings:
        severity_counts[f.severity] += 1

    return ScanResponse(
        scan_id=scan_id,
        name=req.name,
        status=status,
        risk_scores=_scores_to_response(scores),
        findings_count=len(findings),
        findings_summary=severity_counts,
        created_at=created_at,
        completed_at=completed_at,
    )


def _db_scan_to_response(s: dict) -> ScanResponse:
    conn = db.get_connection()
    try:
        summary = db.get_findings_summary(conn, s["scan_id"])
        count = db.get_findings_count(conn, s["scan_id"])
    finally:
        conn.close()
    return ScanResponse(
        scan_id=s["scan_id"],
        name=s["name"],
        status=s.get("status", "completed"),
        risk_scores=RiskScoresResponse(
            domain_scores=DomainScoresResponse(
                prompt_risk=s["prompt_risk"],
                tool_risk=s["tool_risk"],
                output_risk=s["output_risk"],
            ),
            blast_radius=s["blast_radius"],
            composite=s["composite"],
            tier=s["risk_tier"],
        ),
        findings_count=count,
        findings_summary=summary,
        created_at=s["created_at"],
        completed_at=s.get("completed_at"),
    )


def _db_finding_to_response(f: dict) -> FindingResponse:
    return FindingResponse(
        check_id=f["check_id"],
        severity=f["severity"],
        confidence=f["confidence"],
        evidence=EvidenceResponse(
            observable=f["observable"],
            file_path=f["file_path"],
            line=f["line"],
            line_end=f["line_end"],
            raw_value=f["raw_value"],
            context=f["context"],
        ),
        remediation=FindingRemediationResponse(
            description=f["remediation_desc"],
            steps=f["remediation_steps"],
            references=f["remediation_refs"],
            effort=f["remediation_effort"],
        ),
        taxonomy_primary=TaxonomyEntryResponse(
            framework=f["taxonomy_primary_framework"],
            entry_id=f["taxonomy_primary_entry_id"],
            justification=f["taxonomy_primary_justification"],
        ),
        taxonomy_secondary=[
            TaxonomyEntryResponse(**t) for t in f["taxonomy_secondary"]
        ],
    )


@router.get("", response_model=list[ScanResponse])
def list_scans_endpoint():
    """List all scans."""
    conn = db.get_connection()
    try:
        scans = db.list_scans(conn)
    finally:
        conn.close()
    return [_db_scan_to_response(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str):
    """Get a scan by ID."""
    conn = db.get_connection()
    try:
        s = db.get_scan(conn, scan_id)
    finally:
        conn.close()
    if s is None:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return _db_scan_to_response(s)


@router.get("/{scan_id}/risk", response_model=RiskScoresResponse)
def get_risk_scores(scan_id: str):
    """Get risk scores for a scan."""
    conn = db.get_connection()
    try:
        s = db.get_scan(conn, scan_id)
    finally:
        conn.close()
    if s is None:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return RiskScoresResponse(
        domain_scores=DomainScoresResponse(
            prompt_risk=s["prompt_risk"],
            tool_risk=s["tool_risk"],
            output_risk=s["output_risk"],
        ),
        blast_radius=s["blast_radius"],
        composite=s["composite"],
        tier=s["risk_tier"],
    )


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def get_findings(scan_id: str):
    """Get all findings for a scan."""
    conn = db.get_connection()
    try:
        s = db.get_scan(conn, scan_id)
        if s is None:
            raise HTTPException(404, f"Scan {scan_id} not found")
        findings = db.get_findings(conn, scan_id)
    finally:
        conn.close()
    return [_db_finding_to_response(f) for f in findings]
