import Link from "next/link";

export default function Home() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] gap-8">
      <div className="text-center">
        <h1 className="text-5xl font-bold tracking-tight mb-4">
          <span className="text-[var(--accent)]">REAPER</span>
        </h1>
        <p className="text-xl text-[var(--muted)] max-w-lg">
          AI Agent Vulnerability Scanner. Find what your agent exposes before attackers do.
        </p>
      </div>

      <div className="flex gap-4">
        <Link
          href="/scan"
          className="px-6 py-3 bg-[var(--accent)] text-white font-medium rounded-lg hover:bg-[var(--accent-muted)] transition-colors"
        >
          Start a Scan
        </Link>
        <Link
          href="/catalog"
          className="px-6 py-3 border border-[var(--card-border)] rounded-lg hover:border-[var(--accent)] transition-colors"
        >
          Browse Threats
        </Link>
      </div>

      <div className="grid grid-cols-3 gap-6 mt-8 text-center">
        <div className="p-6 rounded-lg border border-[var(--card-border)] bg-[var(--card)]">
          <div className="text-3xl font-bold text-[var(--accent)]">55</div>
          <div className="text-sm text-[var(--muted)] mt-1">Vulnerability Classes</div>
        </div>
        <div className="p-6 rounded-lg border border-[var(--card-border)] bg-[var(--card)]">
          <div className="text-3xl font-bold text-[var(--accent)]">10</div>
          <div className="text-sm text-[var(--muted)] mt-1">OWASP ASI Categories</div>
        </div>
        <div className="p-6 rounded-lg border border-[var(--card-border)] bg-[var(--card)]">
          <div className="text-3xl font-bold text-[var(--accent)]">183</div>
          <div className="text-sm text-[var(--muted)] mt-1">Attack Payloads</div>
        </div>
      </div>
    </div>
  );
}
