"""SQLite database module for REAPER scan persistence."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "reaper.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id            TEXT PRIMARY KEY,
    name               TEXT NOT NULL DEFAULT 'Untitled Scan',
    status             TEXT NOT NULL DEFAULT 'pending',
    framework          TEXT NOT NULL DEFAULT 'unknown',
    prompt_risk        REAL NOT NULL DEFAULT 0,
    tool_risk          REAL NOT NULL DEFAULT 0,
    output_risk        REAL NOT NULL DEFAULT 0,
    blast_radius       REAL NOT NULL DEFAULT 1.0,
    composite          REAL NOT NULL DEFAULT 0,
    risk_tier          TEXT NOT NULL DEFAULT 'low',
    checks_executed    INTEGER NOT NULL DEFAULT 0,
    checks_skipped     INTEGER NOT NULL DEFAULT 0,
    duration_ms        REAL NOT NULL DEFAULT 0,
    recon_profile_json TEXT,
    target_config_json TEXT,
    created_at         TEXT NOT NULL,
    completed_at       TEXT,
    errors_json        TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id                        TEXT NOT NULL REFERENCES scans(scan_id),
    check_id                       TEXT NOT NULL,
    severity                       TEXT NOT NULL,
    confidence                     TEXT NOT NULL,
    observable                     TEXT NOT NULL,
    file_path                      TEXT,
    line                           INTEGER,
    line_end                       INTEGER,
    raw_value                      TEXT NOT NULL,
    context_json                   TEXT,
    remediation_desc               TEXT NOT NULL,
    remediation_steps_json         TEXT,
    remediation_refs_json          TEXT,
    remediation_effort             TEXT NOT NULL,
    taxonomy_primary_framework     TEXT NOT NULL,
    taxonomy_primary_entry_id      TEXT NOT NULL,
    taxonomy_primary_justification TEXT NOT NULL,
    taxonomy_secondary_json        TEXT,
    aasv_vuln_id                   TEXT,
    created_at                     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_check_id ON findings(check_id);
"""


def get_connection() -> sqlite3.Connection:
    """Get a SQLite connection with WAL mode and foreign keys enabled."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    conn = get_connection()
    conn.executescript(SCHEMA_SQL)
    conn.close()


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

def insert_scan(
    conn: sqlite3.Connection,
    scan_id: str,
    name: str,
    status: str,
    framework: str,
    scores: dict,
    checks_executed: int,
    checks_skipped: int,
    duration_ms: float,
    recon_profile: dict | None,
    target_config: dict | None,
    created_at: str,
    completed_at: str | None,
    errors: list[str],
) -> None:
    conn.execute(
        """INSERT INTO scans (
            scan_id, name, status, framework,
            prompt_risk, tool_risk, output_risk,
            blast_radius, composite, risk_tier,
            checks_executed, checks_skipped, duration_ms,
            recon_profile_json, target_config_json,
            created_at, completed_at, errors_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_id, name, status, framework,
            scores.get("prompt_risk", 0),
            scores.get("tool_risk", 0),
            scores.get("output_risk", 0),
            scores.get("blast_radius", 1.0),
            scores.get("composite", 0),
            scores.get("tier", "low"),
            checks_executed, checks_skipped, duration_ms,
            json.dumps(recon_profile) if recon_profile else None,
            json.dumps(target_config) if target_config else None,
            created_at, completed_at,
            json.dumps(errors) if errors else None,
        ),
    )
    conn.commit()


def get_scan(conn: sqlite3.Connection, scan_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    return _scan_row_to_dict(row)


def list_scans(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
    return [_scan_row_to_dict(r) for r in rows]


def _scan_row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a scan row to a dict with findings summary."""
    d = dict(row)
    d["errors"] = json.loads(d["errors_json"]) if d["errors_json"] else []
    return d


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def insert_finding(conn: sqlite3.Connection, scan_id: str, finding) -> None:
    """Insert an sdk.Finding into the database."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO findings (
            scan_id, check_id, severity, confidence,
            observable, file_path, line, line_end, raw_value, context_json,
            remediation_desc, remediation_steps_json, remediation_refs_json, remediation_effort,
            taxonomy_primary_framework, taxonomy_primary_entry_id, taxonomy_primary_justification,
            taxonomy_secondary_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_id,
            finding.check_id,
            finding.severity,
            finding.confidence,
            finding.evidence.observable,
            finding.evidence.file_path,
            finding.evidence.line,
            finding.evidence.line_end,
            finding.evidence.raw_value,
            json.dumps(finding.evidence.context) if finding.evidence.context else None,
            finding.remediation.description,
            json.dumps(finding.remediation.steps),
            json.dumps(finding.remediation.references),
            finding.remediation.effort,
            finding.taxonomy.primary.framework,
            finding.taxonomy.primary.entry_id,
            finding.taxonomy.primary.justification,
            json.dumps([
                {"framework": s.framework, "entry_id": s.entry_id, "justification": s.justification}
                for s in finding.taxonomy.secondary
            ]),
            now,
        ),
    )


def get_findings(conn: sqlite3.Connection, scan_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM findings WHERE scan_id = ? ORDER BY finding_id", (scan_id,)
    ).fetchall()
    return [_finding_row_to_dict(r) for r in rows]


def get_findings_summary(conn: sqlite3.Connection, scan_id: str) -> dict[str, int]:
    """Get severity counts for a scan's findings."""
    rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM findings WHERE scan_id = ? GROUP BY severity",
        (scan_id,),
    ).fetchall()
    return {r["severity"]: r["cnt"] for r in rows}


def get_findings_count(conn: sqlite3.Connection, scan_id: str) -> int:
    row = conn.execute("SELECT COUNT(*) as cnt FROM findings WHERE scan_id = ?", (scan_id,)).fetchone()
    return row["cnt"] if row else 0


def _finding_row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["context"] = json.loads(d["context_json"]) if d["context_json"] else {}
    d["remediation_steps"] = json.loads(d["remediation_steps_json"]) if d["remediation_steps_json"] else {}
    d["remediation_refs"] = json.loads(d["remediation_refs_json"]) if d["remediation_refs_json"] else []
    d["taxonomy_secondary"] = json.loads(d["taxonomy_secondary_json"]) if d["taxonomy_secondary_json"] else []
    return d
