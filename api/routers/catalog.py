"""Catalog API — browse OWASP categories and AASV vulnerability records."""

from pathlib import Path

from fastapi import APIRouter, HTTPException

from reaper.models import load_owasp_categories, load_aasv_bundle, load_all_aasv_bundles
from api.schemas.catalog import (
    OWASPCategoryResponse,
    VulnerabilityListItem,
    VulnerabilityDetailResponse,
    TestCaseResponse,
    PayloadResponse,
    PrerequisiteResponse,
    RemediationResponse,
)

router = APIRouter(prefix="/api/catalog", tags=["catalog"])

CATALOG_ROOT = Path(__file__).resolve().parent.parent.parent / "catalogue"


@router.get("/categories", response_model=list[OWASPCategoryResponse])
def list_categories():
    """List all OWASP ASI 2026 categories."""
    seed_path = CATALOG_ROOT / "owasp" / "asi-2026-seed.json"
    if not seed_path.exists():
        raise HTTPException(404, "OWASP seed data not found")
    cats = load_owasp_categories(seed_path)
    return [
        OWASPCategoryResponse(
            owasp_id=c.owasp_id,
            name=c.name,
            description=c.description,
            cwe_ids=c.cwe_ids,
            rank=c.rank,
            scan_domains=c.scan_domains,
            legacy_alias=c.legacy_alias,
        )
        for c in cats
    ]


@router.get("/vulnerabilities", response_model=list[VulnerabilityListItem])
def list_vulnerabilities(
    domain: str | None = None,
    severity: str | None = None,
    owasp_id: str | None = None,
):
    """List all AASV vulnerability records, with optional filters."""
    aasv_dir = CATALOG_ROOT / "aasv"
    if not aasv_dir.exists():
        return []
    bundles = load_all_aasv_bundles(aasv_dir)
    results = []
    for b in bundles:
        v = b.vulnerability
        if domain and v.domain != domain:
            continue
        if severity and v.severity != severity:
            continue
        if owasp_id and v.owasp_category_id != owasp_id:
            continue
        results.append(VulnerabilityListItem(
            vuln_id=v.vuln_id,
            title=v.title,
            domain=v.domain,
            sub_type=v.sub_type,
            owasp_category_id=v.owasp_category_id,
            severity=v.severity,
            status=v.status,
            tags=v.tags,
        ))
    return results


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityDetailResponse)
def get_vulnerability(vuln_id: str):
    """Get full detail for a single AASV vulnerability bundle."""
    bundle_path = CATALOG_ROOT / "aasv" / f"{vuln_id}-complete-bundle.json"
    if not bundle_path.exists():
        raise HTTPException(404, f"Vulnerability {vuln_id} not found")
    b = load_aasv_bundle(bundle_path)
    v = b.vulnerability

    test_cases = [
        TestCaseResponse(
            test_id=tc.test_id,
            title=tc.title,
            scan_mode=tc.scan_mode,
            priority_tier=tc.priority_tier,
            target_interface=tc.target_interface,
            estimated_duration_sec=tc.estimated_duration_sec,
            requires_multi_turn=tc.requires_multi_turn,
            success_criteria=tc.success_criteria,
        )
        for tc in b.test_cases
    ]

    payloads = [
        PayloadResponse(
            payload_id=pl.payload_id,
            test_id=pl.test_id,
            payload_type=pl.payload_type,
            content=pl.content,
            target_model=pl.target_model,
            encoding=pl.encoding,
            effectiveness_score=pl.effectiveness_score,
        )
        for pl in b.payloads
    ]

    prerequisites = [
        PrerequisiteResponse(
            prereq_id=pr.prereq_id,
            field=pr.field,
            operator=pr.operator,
            value=pr.value,
            description=pr.description,
        )
        for pr in b.prerequisites
    ]

    remediation = None
    if b.remediation:
        r = b.remediation
        remediation = RemediationResponse(
            remediation_id=r.remediation_id,
            fix_type=r.fix_type,
            summary=r.summary,
            instructions=r.instructions,
            difficulty=r.difficulty,
            estimated_effort_hours=r.estimated_effort_hours,
            framework_specific=r.framework_specific,
            references=r.references,
        )

    return VulnerabilityDetailResponse(
        vuln_id=v.vuln_id,
        title=v.title,
        domain=v.domain,
        sub_type=v.sub_type,
        owasp_category_id=v.owasp_category_id,
        cwe_ids=v.cwe_ids,
        severity=v.severity,
        description=v.description,
        attack_vector=v.attack_vector,
        attack_complexity=v.attack_complexity,
        exploitability_score=v.exploitability_score,
        known_affected_frameworks=v.known_affected_frameworks,
        framework_specific_notes=v.framework_specific_notes,
        tags=v.tags,
        status=v.status,
        test_cases=test_cases,
        payloads=payloads,
        prerequisites=prerequisites,
        remediation=remediation,
    )
