"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import { api, type VulnerabilityDetail } from "@/lib/api";

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "text-red-400 border-red-400/30 bg-red-400/10",
    high: "text-orange-400 border-orange-400/30 bg-orange-400/10",
    medium: "text-yellow-400 border-yellow-400/30 bg-yellow-400/10",
    low: "text-green-400 border-green-400/30 bg-green-400/10",
  };
  return (
    <span className={`px-3 py-1 rounded border text-sm font-bold uppercase ${colors[severity] || ""}`}>
      {severity}
    </span>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="p-5 rounded-lg border border-[var(--card-border)] bg-[var(--card)]">
      <h2 className="font-semibold mb-3">{title}</h2>
      {children}
    </div>
  );
}

export default function VulnDetailPage({ params }: { params: Promise<{ vulnId: string }> }) {
  const { vulnId } = use(params);
  const [vuln, setVuln] = useState<VulnerabilityDetail | null>(null);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<"tests" | "payloads" | "remediation">("tests");

  useEffect(() => {
    api.getVulnerability(vulnId).then(setVuln).catch((e) => setError(e.message));
  }, [vulnId]);

  if (error) return <p className="text-red-500">Error: {error}</p>;
  if (!vuln) return <p className="text-[var(--muted)]">Loading...</p>;

  return (
    <div className="max-w-4xl mx-auto">
      <Link href="/catalog" className="text-sm text-[var(--muted)] hover:text-[var(--accent)] mb-4 block">
        &larr; Back to Catalog
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <span className="font-mono text-sm text-[var(--muted)]">{vuln.vuln_id}</span>
            <span className="text-xs px-2 py-0.5 rounded bg-[var(--card)] text-[var(--muted)]">{vuln.domain}</span>
            <span className="text-xs font-mono">{vuln.owasp_category_id}</span>
          </div>
          <h1 className="text-2xl font-bold">{vuln.title}</h1>
        </div>
        <SeverityBadge severity={vuln.severity} />
      </div>

      {/* Description */}
      <Section title="Description">
        <p className="text-sm text-[var(--muted)] whitespace-pre-line">{vuln.description}</p>
        <div className="flex gap-4 mt-4 text-xs text-[var(--muted)]">
          <span>Attack Vector: <strong className="text-[var(--foreground)]">{vuln.attack_vector}</strong></span>
          <span>Complexity: <strong className="text-[var(--foreground)]">{vuln.attack_complexity}</strong></span>
          <span>Exploitability: <strong className="text-[var(--foreground)]">{vuln.exploitability_score}/10</strong></span>
        </div>
        <div className="flex gap-2 mt-3 flex-wrap">
          {vuln.cwe_ids.map((cwe) => (
            <span key={cwe} className="text-xs px-2 py-0.5 bg-[var(--background)] rounded font-mono">{cwe}</span>
          ))}
          {vuln.tags.map((tag) => (
            <span key={tag} className="text-xs px-2 py-0.5 bg-[var(--background)] rounded">{tag}</span>
          ))}
        </div>
      </Section>

      {/* Tabs */}
      <div className="flex gap-1 mt-6 mb-4">
        {(["tests", "payloads", "remediation"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm rounded-lg transition-colors ${
              activeTab === tab
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--card)] text-[var(--muted)] hover:text-[var(--foreground)]"
            }`}
          >
            {tab === "tests" && `Test Cases (${vuln.test_cases.length})`}
            {tab === "payloads" && `Payloads (${vuln.payloads.length})`}
            {tab === "remediation" && "Remediation"}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === "tests" && (
        <div className="space-y-3">
          {vuln.test_cases.map((tc) => (
            <div key={tc.test_id} className="p-4 rounded-lg border border-[var(--card-border)] bg-[var(--card)]">
              <div className="flex items-center gap-3 mb-2">
                <span className="font-mono text-xs text-[var(--muted)]">{tc.test_id}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-[var(--background)]">{tc.scan_mode}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-[var(--background)]">Tier {tc.priority_tier}</span>
                <span className="text-xs text-[var(--muted)]">{tc.estimated_duration_sec}s</span>
              </div>
              <p className="text-sm font-medium mb-2">{tc.title}</p>
              <p className="text-xs text-[var(--muted)]">{tc.success_criteria}</p>
            </div>
          ))}
        </div>
      )}

      {activeTab === "payloads" && (
        <div className="space-y-3">
          {vuln.payloads.map((pl) => (
            <div key={pl.payload_id} className="p-4 rounded-lg border border-[var(--card-border)] bg-[var(--card)]">
              <div className="flex items-center gap-3 mb-2">
                <span className="font-mono text-xs text-[var(--muted)]">{pl.payload_id}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-[var(--background)]">{pl.encoding}</span>
                <span className="text-xs text-[var(--muted)]">
                  Effectiveness: <span className="font-mono">{(pl.effectiveness_score * 100).toFixed(0)}%</span>
                </span>
              </div>
              <pre className="text-xs bg-[var(--background)] p-3 rounded-lg overflow-x-auto whitespace-pre-wrap font-mono">
                {pl.content}
              </pre>
            </div>
          ))}
        </div>
      )}

      {activeTab === "remediation" && vuln.remediation && (
        <Section title="Remediation">
          <div className="flex gap-4 mb-4 text-xs text-[var(--muted)]">
            <span>Fix Type: <strong className="text-[var(--foreground)]">{vuln.remediation.fix_type}</strong></span>
            <span>Difficulty: <strong className="text-[var(--foreground)]">{vuln.remediation.difficulty}</strong></span>
            <span>Effort: <strong className="text-[var(--foreground)]">{vuln.remediation.estimated_effort_hours}h</strong></span>
          </div>
          <p className="text-sm mb-4">{vuln.remediation.summary}</p>
          <div className="text-xs text-[var(--muted)] whitespace-pre-line bg-[var(--background)] p-4 rounded-lg">
            {vuln.remediation.instructions}
          </div>
          {Object.keys(vuln.remediation.framework_specific).length > 0 && (
            <div className="mt-4 space-y-3">
              <h3 className="text-sm font-semibold">Framework-Specific Guidance</h3>
              {Object.entries(vuln.remediation.framework_specific).map(([fw, guidance]) => (
                <div key={fw} className="p-3 rounded bg-[var(--background)]">
                  <span className="text-xs font-mono text-[var(--accent)]">{fw}</span>
                  <p className="text-xs text-[var(--muted)] mt-1 whitespace-pre-line">{guidance}</p>
                </div>
              ))}
            </div>
          )}
        </Section>
      )}
    </div>
  );
}
