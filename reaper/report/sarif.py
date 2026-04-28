"""
SARIF report formatter.

Produces SARIF v2.1.0 output for IDE integration (VS Code, GitHub Code Scanning).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from reaper import __version__
from reaper.engine import ScanResult
from reaper.sdk import Finding

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def generate(results: list[ScanResult]) -> str:
    """Generate a SARIF v2.1.0 report from scan results."""
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for scan_result in results:
        for finding in scan_result.findings:
            rule = _make_rule(finding)
            rules[finding.check_id] = rule
            sarif_results.append(_make_result(finding))

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "REAPER",
                        "version": __version__,
                        "informationUri": "https://github.com/onemanops/reaper",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)


def _make_rule(finding: Finding) -> dict:
    return {
        "id": finding.check_id,
        "shortDescription": {"text": finding.evidence.observable},
        "helpUri": finding.remediation.references[0] if finding.remediation.references else "",
        "defaultConfiguration": {
            "level": SEVERITY_TO_SARIF.get(finding.severity, "note"),
        },
    }


def _make_result(finding: Finding) -> dict:
    result: dict = {
        "ruleId": finding.check_id,
        "level": SEVERITY_TO_SARIF.get(finding.severity, "note"),
        "message": {"text": finding.evidence.observable},
    }
    if finding.evidence.file_path:
        location: dict = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.evidence.file_path},
            }
        }
        if finding.evidence.line is not None:
            region: dict = {"startLine": finding.evidence.line}
            if finding.evidence.line_end is not None:
                region["endLine"] = finding.evidence.line_end
            location["physicalLocation"]["region"] = region
        result["locations"] = [location]
    return result
