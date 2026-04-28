"""Pydantic schemas for catalog API endpoints."""

from pydantic import BaseModel


class OWASPCategoryResponse(BaseModel):
    owasp_id: str
    name: str
    description: str
    cwe_ids: list[str]
    rank: int
    scan_domains: list[str]
    legacy_alias: str


class VulnerabilityListItem(BaseModel):
    vuln_id: str
    title: str
    domain: str
    sub_type: str
    owasp_category_id: str
    severity: str
    status: str
    tags: list[str]


class TestCaseResponse(BaseModel):
    test_id: str
    title: str
    scan_mode: str
    priority_tier: int
    target_interface: str
    estimated_duration_sec: int
    requires_multi_turn: bool
    success_criteria: str


class PayloadResponse(BaseModel):
    payload_id: str
    test_id: str
    payload_type: str
    content: str
    target_model: str
    encoding: str
    effectiveness_score: float


class PrerequisiteResponse(BaseModel):
    prereq_id: str
    field: str
    operator: str
    value: str | int | float | bool | None
    description: str


class RemediationResponse(BaseModel):
    remediation_id: str
    fix_type: str
    summary: str
    instructions: str
    difficulty: str
    estimated_effort_hours: int
    framework_specific: dict[str, str]
    references: list[str]


class VulnerabilityDetailResponse(BaseModel):
    vuln_id: str
    title: str
    domain: str
    sub_type: str
    owasp_category_id: str
    cwe_ids: list[str]
    severity: str
    description: str
    attack_vector: str
    attack_complexity: str
    exploitability_score: float
    known_affected_frameworks: list[str]
    framework_specific_notes: dict[str, str]
    tags: list[str]
    status: str
    test_cases: list[TestCaseResponse]
    payloads: list[PayloadResponse]
    prerequisites: list[PrerequisiteResponse]
    remediation: RemediationResponse | None
