const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function fetchAPI<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

// --- Types ---

export interface DomainScores {
  prompt_risk: number;
  tool_risk: number;
  output_risk: number;
}

export interface RiskScores {
  domain_scores: DomainScores;
  blast_radius: number;
  composite: number;
  tier: string;
}

export interface ScanResponse {
  scan_id: string;
  name: string;
  status: string;
  risk_scores: RiskScores;
  findings_count: number;
  findings_summary: Record<string, number>;
  created_at: string;
  completed_at: string | null;
}

export interface FindingEvidence {
  observable: string;
  file_path: string | null;
  line: number | null;
  line_end: number | null;
  raw_value: string;
  context: Record<string, string>;
}

export interface FindingRemediation {
  description: string;
  steps: Record<string, string>;
  references: string[];
  effort: string;
}

export interface TaxonomyEntry {
  framework: string;
  entry_id: string;
  justification: string;
}

export interface Finding {
  check_id: string;
  severity: string;
  confidence: string;
  evidence: FindingEvidence;
  remediation: FindingRemediation;
  taxonomy_primary: TaxonomyEntry;
  taxonomy_secondary: TaxonomyEntry[];
}

export interface McpServerInput {
  name: string;
  command?: string | null;
  args?: string[];
  env?: Record<string, string>;
  auth?: Record<string, unknown> | null;
}

export interface TargetConfigInput {
  framework: string;
  mcp_servers: McpServerInput[];
  tools?: Record<string, unknown>[];
  system_prompt?: string | null;
  config?: Record<string, unknown>;
  files?: Record<string, string>;
}

export interface OWASPCategory {
  owasp_id: string;
  name: string;
  description: string;
  cwe_ids: string[];
  rank: number;
  scan_domains: string[];
  legacy_alias: string;
}

export interface VulnerabilityListItem {
  vuln_id: string;
  title: string;
  domain: string;
  sub_type: string;
  owasp_category_id: string;
  severity: string;
  status: string;
  tags: string[];
}

export interface TestCase {
  test_id: string;
  title: string;
  scan_mode: string;
  priority_tier: number;
  target_interface: string;
  estimated_duration_sec: number;
  requires_multi_turn: boolean;
  success_criteria: string;
}

export interface Payload {
  payload_id: string;
  test_id: string;
  payload_type: string;
  content: string;
  target_model: string;
  encoding: string;
  effectiveness_score: number;
}

export interface Prerequisite {
  prereq_id: string;
  field: string;
  operator: string;
  value: string | number | boolean | null;
  description: string;
}

export interface Remediation {
  remediation_id: string;
  fix_type: string;
  summary: string;
  instructions: string;
  difficulty: string;
  estimated_effort_hours: number;
  framework_specific: Record<string, string>;
  references: string[];
}

export interface VulnerabilityDetail {
  vuln_id: string;
  title: string;
  domain: string;
  sub_type: string;
  owasp_category_id: string;
  cwe_ids: string[];
  severity: string;
  description: string;
  attack_vector: string;
  attack_complexity: string;
  exploitability_score: number;
  known_affected_frameworks: string[];
  framework_specific_notes: Record<string, string>;
  tags: string[];
  status: string;
  test_cases: TestCase[];
  payloads: Payload[];
  prerequisites: Prerequisite[];
  remediation: Remediation | null;
}

export interface ScanCreateRequest {
  name: string;
  agent_identity: {
    autonomy_level: number;
    model_hardening: number;
    framework: string;
    model_provider: string;
  };
  tool_inventory: {
    tool_count: number;
    write_capable_pct: number;
    auth_mechanism: string;
    mcp_servers: string[];
  };
  data_exposure: {
    pii_in_context: number;
    untrusted_rag_sources: number;
    data_stores_accessible: string[];
    secrets_in_prompt: boolean;
  };
  guardrails: {
    input_filter_strength: number;
    hitl_coverage_pct: number;
    output_filter_strength: number;
    instruction_hierarchy: boolean;
  };
  target?: TargetConfigInput | null;
}

// --- API functions ---

export const api = {
  health: () => fetchAPI<{ status: string; version: string }>("/api/health"),

  getCategories: () => fetchAPI<OWASPCategory[]>("/api/catalog/categories"),

  getVulnerabilities: (params?: { domain?: string; severity?: string; owasp_id?: string }) => {
    const search = new URLSearchParams();
    if (params?.domain) search.set("domain", params.domain);
    if (params?.severity) search.set("severity", params.severity);
    if (params?.owasp_id) search.set("owasp_id", params.owasp_id);
    const qs = search.toString();
    return fetchAPI<VulnerabilityListItem[]>(`/api/catalog/vulnerabilities${qs ? `?${qs}` : ""}`);
  },

  getVulnerability: (vulnId: string) =>
    fetchAPI<VulnerabilityDetail>(`/api/catalog/vulnerabilities/${vulnId}`),

  createScan: (data: ScanCreateRequest) =>
    fetchAPI<ScanResponse>("/api/scans", { method: "POST", body: JSON.stringify(data) }),

  getScans: () => fetchAPI<ScanResponse[]>("/api/scans"),

  getScan: (scanId: string) => fetchAPI<ScanResponse>(`/api/scans/${scanId}`),

  getRiskScores: (scanId: string) => fetchAPI<RiskScores>(`/api/scans/${scanId}/risk`),

  getFindings: (scanId: string) => fetchAPI<Finding[]>(`/api/scans/${scanId}/findings`),
};
