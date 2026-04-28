"""
REAPER Scanner Engine — Check discovery, loading, execution, and orchestration.

Loads checks from local directory and optional remote pro feed,
executes them against targets provided by framework adapters,
and collects findings for the reporting engine.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from reaper.sdk import (
    Finding,
    ProbeTarget,
    ReaperCheck,
    SessionContext,
    TargetConfig,
)

logger = logging.getLogger("reaper")

SUPPORTED_CONTRACT_VERSIONS = {"1.0", "2.0"}


# ---------------------------------------------------------------------------
# Scan Result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Aggregate output of a scan run."""

    target_framework: str
    target_metadata: dict
    findings: list[Finding] = field(default_factory=list)
    checks_executed: int = 0
    checks_skipped: int = 0
    probes_executed: int = 0
    duration_ms: float = 0.0
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Check Loader
# ---------------------------------------------------------------------------

class CheckLoader:
    """Discovers and loads ReaperCheck subclasses from a directory of Python modules."""

    def __init__(self, checks_dir: str | Path) -> None:
        self.checks_dir = Path(checks_dir)

    def load_all(self) -> list[ReaperCheck]:
        """Load all conforming checks from the checks directory."""
        checks: list[ReaperCheck] = []
        if not self.checks_dir.is_dir():
            logger.warning(f"Checks directory does not exist: {self.checks_dir}")
            return checks

        for py_file in sorted(self.checks_dir.glob("rpr_*.py")):
            loaded = self._load_module(py_file)
            if loaded:
                checks.append(loaded)
        return checks

    def _load_module(self, path: Path) -> ReaperCheck | None:
        """Load a single check module and return an instance of its ReaperCheck subclass."""
        module_name = path.stem
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                logger.error(f"Cannot create module spec for {path}")
                return None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            logger.error(f"Failed to load module {path}: {exc}")
            return None

        # Find the ReaperCheck subclass defined in this module
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, ReaperCheck)
                and obj is not ReaperCheck
                and obj.__module__ == module_name
            ):
                instance = obj()
                errors = instance.validate_metadata()
                if errors:
                    logger.error(
                        f"Check {path.name} failed contract validation: {'; '.join(errors)}"
                    )
                    return None
                if instance.contract_version not in SUPPORTED_CONTRACT_VERSIONS:
                    logger.error(
                        f"Check {instance.check_id} declares contract_version "
                        f"'{instance.contract_version}', engine supports "
                        f"{SUPPORTED_CONTRACT_VERSIONS}"
                    )
                    return None
                logger.info(f"Loaded check {instance.check_id} from {path.name}")
                return instance

        logger.warning(f"No ReaperCheck subclass found in {path.name}")
        return None


# ---------------------------------------------------------------------------
# Scanner Engine
# ---------------------------------------------------------------------------

class ScannerEngine:
    """Core engine: loads checks, runs them against adapter-provided targets."""

    def __init__(self, checks_dir: str | Path = "checks") -> None:
        self.loader = CheckLoader(checks_dir)
        self.checks: list[ReaperCheck] = []

    def load_checks(self) -> int:
        """Load all checks. Returns count of successfully loaded checks."""
        self.checks = self.loader.load_all()
        logger.info(f"Loaded {len(self.checks)} checks")
        return len(self.checks)

    def scan(self, target: TargetConfig) -> ScanResult:
        """Execute all applicable checks against a single target."""
        result = ScanResult(
            target_framework=target.framework,
            target_metadata=target.metadata,
        )
        start = time.monotonic()

        for check in self.checks:
            # Framework filtering: skip checks that don't apply to this target
            if "universal" not in check.frameworks and target.framework not in check.frameworks:
                result.checks_skipped += 1
                continue

            try:
                finding = check.detect(target)
                result.checks_executed += 1
                if finding is not None:
                    result.findings.append(finding)
            except Exception as exc:
                result.errors.append(f"{check.check_id}: {exc}")
                logger.error(f"Check {check.check_id} raised an exception: {exc}")

        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    def probe_scan(self, targets: list[ProbeTarget]) -> ScanResult:
        """Execute Wedge 2 checks against probe targets."""
        result = ScanResult(
            target_framework="probe",
            target_metadata={"probe_targets": len(targets)},
        )
        start = time.monotonic()

        wedge2_checks = [c for c in self.checks if c.wedge == 2]
        if not wedge2_checks:
            logger.warning("No Wedge 2 checks loaded")
            result.duration_ms = (time.monotonic() - start) * 1000
            return result

        session = SessionContext()
        session._transport_factory = True  # Signal that transport is available

        for target in targets:
            for check in wedge2_checks:
                if (
                    "universal" not in check.frameworks
                    and target.metadata.get("framework") not in check.frameworks
                    and "mcp_generic" not in check.frameworks
                ):
                    result.checks_skipped += 1
                    continue

                try:
                    finding = check.probe(target, session)
                    result.probes_executed += 1
                    result.checks_executed += 1
                    if finding is not None:
                        result.findings.append(finding)
                except Exception as exc:
                    result.errors.append(f"{check.check_id}: {exc}")
                    logger.error(f"Check {check.check_id} probe raised: {exc}")

        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    def scan_multiple(self, targets: list[TargetConfig]) -> list[ScanResult]:
        """Scan multiple targets sequentially."""
        return [self.scan(target) for target in targets]

    def get_check_ids(self) -> list[str]:
        """Return IDs of all loaded checks."""
        return [c.check_id for c in self.checks]

    def get_check(self, check_id: str) -> ReaperCheck | None:
        """Look up a loaded check by ID."""
        for c in self.checks:
            if c.check_id == check_id:
                return c
        return None
