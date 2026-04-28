"""Tests for the REAPER scanner engine — check loading and execution."""

import pytest

from reaper.engine import ScannerEngine
from reaper.sdk import TargetConfig


@pytest.fixture
def engine(tmp_path):
    """Engine loaded with the real checks directory."""
    import shutil
    from pathlib import Path

    checks_src = Path(__file__).parent.parent / "checks"
    checks_dst = tmp_path / "checks"
    shutil.copytree(checks_src, checks_dst)
    eng = ScannerEngine(checks_dst)
    eng.load_checks()
    return eng


def _make_target(mcp_servers: list[dict], framework: str = "openclaw") -> TargetConfig:
    return TargetConfig(
        framework=framework,
        config={},
        tools=[],
        mcp_servers=mcp_servers,
        system_prompt=None,
        files={},
        metadata={"config_path": "test/config.json"},
    )


class TestCheckLoading:
    def test_loads_reference_check(self, engine):
        assert len(engine.checks) >= 1
        ids = engine.get_check_ids()
        assert "RPR-CONF-001" in ids

    def test_get_check_by_id(self, engine):
        check = engine.get_check("RPR-CONF-001")
        assert check is not None
        assert check.name == "MCP Server Missing Authentication"

    def test_get_nonexistent_check(self, engine):
        assert engine.get_check("RPR-CONF-999") is None


class TestScanning:
    def test_detects_missing_auth(self, engine):
        target = _make_target([{"name": "my-tools"}])
        result = engine.scan(target)
        assert len(result.findings) >= 1
        conf001 = [f for f in result.findings if f.check_id == "RPR-CONF-001"]
        assert len(conf001) == 1
        assert conf001[0].severity == "high"

    def test_detects_auth_type_none(self, engine):
        target = _make_target([{"name": "srv", "auth": {"type": "none"}}])
        result = engine.scan(target)
        conf001 = [f for f in result.findings if f.check_id == "RPR-CONF-001"]
        assert len(conf001) == 1

    def test_detects_empty_token(self, engine):
        target = _make_target([{"name": "srv", "auth": {"type": "bearer", "token": ""}}])
        result = engine.scan(target)
        conf001 = [f for f in result.findings if f.check_id == "RPR-CONF-001"]
        assert len(conf001) == 1

    def test_detects_placeholder_token(self, engine):
        target = _make_target([{"name": "srv", "auth": {"type": "bearer", "token": "changeme"}}])
        result = engine.scan(target)
        conf001 = [f for f in result.findings if f.check_id == "RPR-CONF-001"]
        assert len(conf001) == 1

    def test_safe_config_no_findings_for_auth(self, engine):
        target = _make_target([
            {"name": "srv", "auth": {"type": "bearer", "token": "sk-prod-abc123def456"}}
        ])
        result = engine.scan(target)
        conf001 = [f for f in result.findings if f.check_id == "RPR-CONF-001"]
        assert len(conf001) == 0

    def test_skips_wrong_framework(self, engine):
        target = _make_target([{"name": "srv"}], framework="crewai")
        result = engine.scan(target)
        assert result.checks_skipped >= 1
        # RPR-CONF-001 only supports openclaw/mcp_generic — should be skipped for crewai
        conf001 = [f for f in result.findings if f.check_id == "RPR-CONF-001"]
        assert len(conf001) == 0

    def test_scan_multiple(self, engine):
        targets = [
            _make_target([{"name": "a"}]),
            _make_target([{"name": "b", "auth": {"type": "bearer", "token": "real-token"}}]),
        ]
        results = engine.scan_multiple(targets)
        assert len(results) == 2
        # First target has no auth → RPR-CONF-001 should fire
        conf001_a = [f for f in results[0].findings if f.check_id == "RPR-CONF-001"]
        assert len(conf001_a) == 1
        # Second target has auth → RPR-CONF-001 should not fire
        conf001_b = [f for f in results[1].findings if f.check_id == "RPR-CONF-001"]
        assert len(conf001_b) == 0
