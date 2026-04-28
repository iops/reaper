"""
JSON report formatter.

Produces structured JSON output suitable for CI/CD pipelines,
programmatic consumption, and feeding into other tools.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone

from reaper import __version__
from reaper.engine import ScanResult


def generate(results: list[ScanResult], pretty: bool = True) -> str:
    """Generate a JSON report from scan results."""
    report = {
        "reaper_version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": _build_summary(results),
        "results": [_serialize_result(r) for r in results],
    }
    return json.dumps(report, indent=2 if pretty else None, default=str)


def _build_summary(results: list[ScanResult]) -> dict:
    total_findings = sum(len(r.findings) for r in results)
    severity_counts: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    return {
        "targets_scanned": len(results),
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "total_checks_executed": sum(r.checks_executed for r in results),
        "total_checks_skipped": sum(r.checks_skipped for r in results),
        "total_errors": sum(len(r.errors) for r in results),
    }


def _serialize_result(result: ScanResult) -> dict:
    return {
        "target_framework": result.target_framework,
        "target_metadata": result.target_metadata,
        "checks_executed": result.checks_executed,
        "checks_skipped": result.checks_skipped,
        "duration_ms": round(result.duration_ms, 2),
        "findings": [asdict(f) for f in result.findings],
        "errors": result.errors,
    }
