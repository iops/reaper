"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, type VulnerabilityListItem } from "@/lib/api";

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "text-red-400 border-red-400/30 bg-red-400/10",
    high: "text-orange-400 border-orange-400/30 bg-orange-400/10",
    medium: "text-yellow-400 border-yellow-400/30 bg-yellow-400/10",
    low: "text-green-400 border-green-400/30 bg-green-400/10",
    info: "text-blue-400 border-blue-400/30 bg-blue-400/10",
  };
  return (
    <span className={`px-2 py-0.5 rounded border text-xs font-medium uppercase ${colors[severity] || ""}`}>
      {severity}
    </span>
  );
}

function DomainBadge({ domain }: { domain: string }) {
  const colors: Record<string, string> = {
    prompt: "text-purple-400 bg-purple-400/10",
    tool: "text-blue-400 bg-blue-400/10",
    output: "text-emerald-400 bg-emerald-400/10",
    config: "text-amber-400 bg-amber-400/10",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[domain] || "bg-[var(--card)]"}`}>
      {domain}
    </span>
  );
}

export default function CatalogPage() {
  const [vulns, setVulns] = useState<VulnerabilityListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [domainFilter, setDomainFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    api
      .getVulnerabilities({
        domain: domainFilter || undefined,
        severity: severityFilter || undefined,
      })
      .then(setVulns)
      .finally(() => setLoading(false));
  }, [domainFilter, severityFilter]);

  const filtered = vulns.filter(
    (v) =>
      !search ||
      v.title.toLowerCase().includes(search.toLowerCase()) ||
      v.vuln_id.toLowerCase().includes(search.toLowerCase()) ||
      v.tags.some((t) => t.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div>
      <h1 className="text-2xl font-bold mb-2">Threat Catalog</h1>
      <p className="text-[var(--muted)] text-sm mb-6">
        {vulns.length} vulnerability classes across all scan domains. Each backed by test cases, payloads, and framework-specific remediation.
      </p>

      {/* Filters */}
      <div className="flex gap-3 mb-6 flex-wrap">
        <input
          type="text"
          placeholder="Search vulnerabilities..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="px-3 py-2 bg-[var(--background)] border border-[var(--card-border)] rounded-lg text-sm flex-1 min-w-[200px] focus:border-[var(--accent)] outline-none"
        />
        <select
          value={domainFilter}
          onChange={(e) => setDomainFilter(e.target.value)}
          className="px-3 py-2 bg-[var(--background)] border border-[var(--card-border)] rounded-lg text-sm"
        >
          <option value="">All Domains</option>
          <option value="prompt">Prompt</option>
          <option value="tool">Tool</option>
          <option value="output">Output</option>
          <option value="config">Config</option>
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-2 bg-[var(--background)] border border-[var(--card-border)] rounded-lg text-sm"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Table */}
      {loading ? (
        <p className="text-[var(--muted)]">Loading catalog...</p>
      ) : (
        <div className="border border-[var(--card-border)] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-[var(--card)] border-b border-[var(--card-border)]">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-[var(--muted)]">ID</th>
                <th className="text-left px-4 py-3 font-medium text-[var(--muted)]">Vulnerability</th>
                <th className="text-left px-4 py-3 font-medium text-[var(--muted)]">Domain</th>
                <th className="text-left px-4 py-3 font-medium text-[var(--muted)]">ASI</th>
                <th className="text-left px-4 py-3 font-medium text-[var(--muted)]">Severity</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((v) => (
                <tr
                  key={v.vuln_id}
                  className="border-b border-[var(--card-border)] hover:bg-[var(--card)] transition-colors"
                >
                  <td className="px-4 py-3 font-mono text-xs text-[var(--muted)]">
                    <Link href={`/catalog/${v.vuln_id}`} className="hover:text-[var(--accent)]">
                      {v.vuln_id}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link href={`/catalog/${v.vuln_id}`} className="hover:text-[var(--accent)]">
                      {v.title}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <DomainBadge domain={v.domain} />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{v.owasp_category_id}</td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={v.severity} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <p className="text-center text-[var(--muted)] py-8">No vulnerabilities match your filters.</p>
          )}
        </div>
      )}
    </div>
  );
}
