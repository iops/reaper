"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { api, type ScanResponse, type Finding } from "@/lib/api";

function TierBadge({ tier }: { tier: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-600 text-white",
    medium: "bg-yellow-600 text-black",
    low: "bg-green-600 text-white",
  };
  return (
    <span className={`px-3 py-1 rounded-full text-sm font-bold uppercase ${colors[tier] || "bg-gray-600"}`}>
      {tier}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-900 text-red-300 border-red-700",
    high: "bg-orange-900 text-orange-300 border-orange-700",
    medium: "bg-yellow-900 text-yellow-300 border-yellow-700",
    low: "bg-green-900 text-green-300 border-green-700",
    info: "bg-blue-900 text-blue-300 border-blue-700",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase border ${colors[severity] || "bg-gray-800 border-gray-600"}`}>
      {severity}
    </span>
  );
}

function FindingCard({ finding, defaultOpen }: { finding: Finding; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen || false);

  return (
    <div className="border border-[var(--card-border)] rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-[var(--background)] transition-colors"
      >
        <SeverityBadge severity={finding.severity} />
        <span className="font-mono text-xs text-[var(--muted)]">{finding.check_id}</span>
        <span className="text-sm flex-1">{finding.evidence.observable}</span>
        <span className="text-xs text-[var(--muted)]">{open ? "\u25B2" : "\u25BC"}</span>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-4 border-t border-[var(--card-border)] bg-[var(--background)]">
          {/* Evidence */}
          <div className="pt-3">
            <h4 className="text-xs font-semibold text-[var(--muted)] uppercase mb-2">Evidence</h4>
            <div className="font-mono text-xs bg-[var(--card)] p-3 rounded border border-[var(--card-border)] whitespace-pre-wrap">
              {finding.evidence.raw_value}
            </div>
            {finding.evidence.file_path && (
              <p className="text-xs text-[var(--muted)] mt-1">File: {finding.evidence.file_path}</p>
            )}
          </div>

          {/* Remediation */}
          <div>
            <h4 className="text-xs font-semibold text-[var(--muted)] uppercase mb-2">Remediation</h4>
            <p className="text-sm mb-2">{finding.remediation.description}</p>
            {Object.entries(finding.remediation.steps).map(([fw, step]) => (
              <details key={fw} className="mb-1">
                <summary className="text-xs font-semibold text-[var(--accent)] cursor-pointer">{fw}</summary>
                <pre className="text-xs bg-[var(--card)] p-2 rounded mt-1 whitespace-pre-wrap border border-[var(--card-border)]">{step}</pre>
              </details>
            ))}
            <p className="text-xs text-[var(--muted)] mt-1">Effort: {finding.remediation.effort}</p>
          </div>

          {/* Taxonomy */}
          <div>
            <h4 className="text-xs font-semibold text-[var(--muted)] uppercase mb-2">Classification</h4>
            <div className="flex flex-wrap gap-2">
              <span className="px-2 py-0.5 bg-[var(--accent)] text-white rounded text-xs font-mono">
                {finding.taxonomy_primary.entry_id}
              </span>
              {finding.taxonomy_secondary.map((t, i) => (
                <span key={i} className="px-2 py-0.5 bg-[var(--card)] border border-[var(--card-border)] rounded text-xs font-mono">
                  {t.entry_id}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ScoreGauge({ label, value, max = 100 }: { label: string; value: number; max?: number }) {
  const pct = Math.min((value / max) * 100, 100);
  const color =
    pct >= 75 ? "bg-red-500" : pct >= 50 ? "bg-orange-500" : pct >= 25 ? "bg-yellow-500" : "bg-green-500";

  return (
    <div className="p-4 rounded-lg border border-[var(--card-border)] bg-[var(--card)]">
      <div className="flex justify-between items-center mb-2">
        <span className="text-sm text-[var(--muted)]">{label}</span>
        <span className="text-lg font-bold font-mono">{value.toFixed(0)}</span>
      </div>
      <div className="h-2 bg-[var(--background)] rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function ResultsContent() {
  const searchParams = useSearchParams();
  const scanId = searchParams.get("id");
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!scanId) return;
    api.getScan(scanId).then(setScan).catch((e) => setError(e.message));
    api.getFindings(scanId).then(setFindings).catch(() => {});
  }, [scanId]);

  if (error) return <p className="text-red-500">Error: {error}</p>;
  if (!scan) return <p className="text-[var(--muted)]">Loading...</p>;

  const { risk_scores: rs } = scan;

  return (
    <div className="max-w-3xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold">{scan.name}</h1>
          <p className="text-sm text-[var(--muted)] mt-1">Scan ID: {scan.scan_id}</p>
        </div>
        <TierBadge tier={rs.tier} />
      </div>

      {/* Composite score */}
      <div className="p-6 rounded-lg border border-[var(--card-border)] bg-[var(--card)] mb-6 text-center">
        <div className="text-sm text-[var(--muted)] mb-2">Composite Risk Score</div>
        <div className="text-6xl font-bold font-mono text-[var(--accent)]">{rs.composite.toFixed(0)}</div>
        <div className="text-sm text-[var(--muted)] mt-2">
          Blast Radius: <span className="font-mono font-bold">{rs.blast_radius.toFixed(1)}x</span>
        </div>
      </div>

      {/* Domain scores */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <ScoreGauge label="Prompt Risk" value={rs.domain_scores.prompt_risk} />
        <ScoreGauge label="Tool Risk" value={rs.domain_scores.tool_risk} />
        <ScoreGauge label="Output Risk" value={rs.domain_scores.output_risk} />
      </div>

      {/* What this means */}
      <div className="p-6 rounded-lg border border-[var(--card-border)] bg-[var(--card)] mb-6">
        <h2 className="font-semibold mb-3">What This Means</h2>
        {rs.tier === "critical" && (
          <p className="text-sm text-[var(--muted)]">
            Your agent has <strong className="text-red-400">critical risk exposure</strong>.
            With high autonomy, write-capable tools, and limited guardrails, an attacker could
            hijack your agent, exfiltrate data, or execute unauthorized actions with minimal effort.
            A full vulnerability scan is strongly recommended.
          </p>
        )}
        {rs.tier === "high" && (
          <p className="text-sm text-[var(--muted)]">
            Your agent has <strong className="text-orange-400">high risk exposure</strong>.
            The combination of autonomy and tool access creates significant attack surface.
            A targeted scan focusing on the highest-scoring domain is recommended.
          </p>
        )}
        {rs.tier === "medium" && (
          <p className="text-sm text-[var(--muted)]">
            Your agent has <strong className="text-yellow-400">moderate risk exposure</strong>.
            Some attack vectors exist but are mitigated by guardrails or limited capability.
            Scanning the top two domains will identify the most impactful vulnerabilities.
          </p>
        )}
        {rs.tier === "low" && (
          <p className="text-sm text-[var(--muted)]">
            Your agent has <strong className="text-green-400">low risk exposure</strong>.
            Strong guardrails and limited capability keep the attack surface small.
            A passive scan will confirm your security posture.
          </p>
        )}
      </div>

      {/* Findings */}
      <div className="p-6 rounded-lg border border-[var(--card-border)] bg-[var(--card)] mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold">Vulnerability Findings</h2>
          {scan.findings_count > 0 ? (
            <div className="flex gap-2">
              {Object.entries(scan.findings_summary).map(([sev, count]) => (
                <span key={sev} className="flex items-center gap-1">
                  <SeverityBadge severity={sev} />
                  <span className="text-xs font-mono">{count}</span>
                </span>
              ))}
            </div>
          ) : (
            <span className="text-xs text-green-400 font-semibold">No vulnerabilities detected</span>
          )}
        </div>

        {findings.length > 0 ? (
          <div className="space-y-2">
            {findings.map((f, i) => (
              <FindingCard key={`${f.check_id}-${i}`} finding={f} defaultOpen={i === 0} />
            ))}
          </div>
        ) : scan.findings_count === 0 ? (
          <p className="text-sm text-[var(--muted)] text-center py-4">
            All checks passed. No vulnerabilities found in the provided configuration.
          </p>
        ) : null}
      </div>

      <div className="flex gap-4">
        <Link
          href="/scan"
          className="px-4 py-2 border border-[var(--card-border)] rounded-lg hover:border-[var(--accent)] transition-colors"
        >
          New Scan
        </Link>
        <Link
          href="/catalog"
          className="px-4 py-2 border border-[var(--card-border)] rounded-lg hover:border-[var(--accent)] transition-colors"
        >
          View Threat Catalog
        </Link>
      </div>
    </div>
  );
}

export default function ResultsPage() {
  return (
    <Suspense fallback={<p className="text-[var(--muted)]">Loading...</p>}>
      <ResultsContent />
    </Suspense>
  );
}
