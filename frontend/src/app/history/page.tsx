"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, type ScanResponse } from "@/lib/api";

function TierBadge({ tier }: { tier: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-600 text-white",
    medium: "bg-yellow-600 text-black",
    low: "bg-green-600 text-white",
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-bold uppercase ${colors[tier] || "bg-gray-600"}`}>
      {tier}
    </span>
  );
}

function SeverityBar({ summary }: { summary: Record<string, number> }) {
  const order = ["critical", "high", "medium", "low", "info"];
  const colors: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-green-500",
    info: "bg-blue-500",
  };
  const total = Object.values(summary).reduce((a, b) => a + b, 0);
  if (total === 0) return <span className="text-xs text-green-400">Clean</span>;

  return (
    <div className="flex gap-0.5 items-center">
      {order.map((sev) =>
        summary[sev] ? (
          <div
            key={sev}
            className={`h-4 rounded-sm ${colors[sev]}`}
            style={{ width: `${Math.max((summary[sev] / total) * 80, 12)}px` }}
            title={`${sev}: ${summary[sev]}`}
          />
        ) : null,
      )}
      <span className="text-xs font-mono ml-2">{total}</span>
    </div>
  );
}

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .getScans()
      .then(setScans)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-2xl font-bold">Scan History</h1>
        <Link
          href="/scan"
          className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg hover:bg-[var(--accent-muted)] transition-colors text-sm"
        >
          New Scan
        </Link>
      </div>

      {error && <p className="text-red-500 mb-4">Error: {error}</p>}

      {loading ? (
        <p className="text-[var(--muted)]">Loading...</p>
      ) : scans.length === 0 ? (
        <div className="text-center py-16 border border-[var(--card-border)] rounded-lg bg-[var(--card)]">
          <p className="text-[var(--muted)] mb-4">No scans yet</p>
          <Link href="/scan" className="text-[var(--accent)] hover:underline text-sm">
            Run your first scan
          </Link>
        </div>
      ) : (
        <div className="border border-[var(--card-border)] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-[var(--card)] border-b border-[var(--card-border)]">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-[var(--muted)]">Name</th>
                <th className="text-left px-4 py-3 font-medium text-[var(--muted)]">Risk</th>
                <th className="text-left px-4 py-3 font-medium text-[var(--muted)]">Score</th>
                <th className="text-left px-4 py-3 font-medium text-[var(--muted)]">Findings</th>
                <th className="text-left px-4 py-3 font-medium text-[var(--muted)]">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--card-border)]">
              {scans.map((scan) => (
                <tr key={scan.scan_id} className="hover:bg-[var(--card)] transition-colors">
                  <td className="px-4 py-3">
                    <Link
                      href={`/scan/results?id=${scan.scan_id}`}
                      className="hover:text-[var(--accent)] transition-colors"
                    >
                      {scan.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <TierBadge tier={scan.risk_scores.tier} />
                  </td>
                  <td className="px-4 py-3 font-mono">
                    {scan.risk_scores.composite.toFixed(0)}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBar summary={scan.findings_summary} />
                  </td>
                  <td className="px-4 py-3 text-[var(--muted)]">
                    {new Date(scan.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
