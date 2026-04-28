"""Pydantic schemas for scan API endpoints."""

from pydantic import BaseModel, Field


class AgentIdentityInput(BaseModel):
    autonomy_level: int = Field(4, ge=0, le=4, description="0=chatbot, 4=fully autonomous")
    model_hardening: int = Field(0, ge=0, le=4, description="0=base model, 4=red-teamed+layered")
    framework: str = "unknown"
    model_provider: str = "unknown"


class ToolInventoryInput(BaseModel):
    tool_count: int = Field(50, ge=0, le=50)
    write_capable_pct: float = Field(100.0, ge=0, le=100)
    auth_mechanism: str = Field("oauth_user", pattern=r"^(none|api_key_static|service_account|oauth_user)$")
    mcp_servers: list[str] = []


class DataExposureInput(BaseModel):
    pii_in_context: int = Field(4, ge=0, le=4, description="0=none, 4=SSN/medical/credentials")
    untrusted_rag_sources: int = Field(4, ge=0, le=4, description="0=none, 4=attacker-influenceable")
    data_stores_accessible: list[str] = []
    secrets_in_prompt: bool = True


class GuardrailsInput(BaseModel):
    input_filter_strength: int = Field(0, ge=0, le=4)
    hitl_coverage_pct: float = Field(0.0, ge=0, le=100)
    output_filter_strength: int = Field(0, ge=0, le=4)
    instruction_hierarchy: bool = False


# --- Target config for scan execution ---


class McpServerInput(BaseModel):
    """A single MCP server entry from the target's config."""
    name: str
    command: str | None = None
    args: list[str] = []
    env: dict[str, str] = {}
    auth: dict | None = None


class TargetConfigInput(BaseModel):
    """Target agent configuration for the scan engine."""
    framework: str = "mcp_generic"
    mcp_servers: list[McpServerInput] = []
    tools: list[dict] = []
    system_prompt: str | None = None
    config: dict = {}
    files: dict[str, str] = {}


class ScanCreateRequest(BaseModel):
    """Request body for POST /api/scans."""
    name: str = Field("Untitled Scan", max_length=200)
    agent_identity: AgentIdentityInput = AgentIdentityInput()
    tool_inventory: ToolInventoryInput = ToolInventoryInput()
    data_exposure: DataExposureInput = DataExposureInput()
    guardrails: GuardrailsInput = GuardrailsInput()
    target: TargetConfigInput | None = None


# --- Response schemas ---


class DomainScoresResponse(BaseModel):
    prompt_risk: float
    tool_risk: float
    output_risk: float


class RiskScoresResponse(BaseModel):
    domain_scores: DomainScoresResponse
    blast_radius: float
    composite: float
    tier: str


class EvidenceResponse(BaseModel):
    observable: str
    file_path: str | None
    line: int | None
    line_end: int | None
    raw_value: str
    context: dict[str, str]


class TaxonomyEntryResponse(BaseModel):
    framework: str
    entry_id: str
    justification: str


class FindingRemediationResponse(BaseModel):
    description: str
    steps: dict[str, str]
    references: list[str]
    effort: str


class FindingResponse(BaseModel):
    check_id: str
    severity: str
    confidence: str
    evidence: EvidenceResponse
    remediation: FindingRemediationResponse
    taxonomy_primary: TaxonomyEntryResponse
    taxonomy_secondary: list[TaxonomyEntryResponse]


class ScanResponse(BaseModel):
    """Response for scan creation and retrieval."""
    scan_id: str
    name: str
    status: str
    risk_scores: RiskScoresResponse
    findings_count: int
    findings_summary: dict[str, int]
    created_at: str
    completed_at: str | None
