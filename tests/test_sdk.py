"""Tests for REAPER SDK data types and validation."""

import pytest

from reaper.sdk import (
    AARFAssessment,
    ReaperCheck,
    SeverityRating,
    TaxonomyEntry,
    TaxonomyMapping,
)


# ---------------------------------------------------------------------------
# TaxonomyEntry
# ---------------------------------------------------------------------------

class TestTaxonomyEntry:
    def test_valid_entry(self):
        entry = TaxonomyEntry(
            framework="owasp_asi", entry_id="ASI04", justification="Test justification"
        )
        assert entry.framework == "owasp_asi"

    def test_invalid_framework(self):
        with pytest.raises(ValueError, match="Unknown taxonomy framework"):
            TaxonomyEntry(framework="bogus", entry_id="X", justification="test")

    def test_empty_justification(self):
        with pytest.raises(ValueError, match="justification must not be empty"):
            TaxonomyEntry(framework="owasp_asi", entry_id="ASI01", justification="")


# ---------------------------------------------------------------------------
# TaxonomyMapping
# ---------------------------------------------------------------------------

class TestTaxonomyMapping:
    def test_primary_must_be_owasp_asi(self):
        with pytest.raises(ValueError, match="must use 'owasp_asi'"):
            TaxonomyMapping(
                primary=TaxonomyEntry(framework="cwe", entry_id="CWE-306", justification="test")
            )


# ---------------------------------------------------------------------------
# SeverityRating
# ---------------------------------------------------------------------------

class TestSeverityRating:
    def test_valid_severity(self):
        s = SeverityRating(default="high", cvss_base=8.2)
        assert s.default == "high"

    def test_invalid_severity(self):
        with pytest.raises(ValueError, match="Severity must be one of"):
            SeverityRating(default="extreme", cvss_base=9.0)

    def test_cvss_required_for_non_info(self):
        with pytest.raises(ValueError, match="CVSS base score is required"):
            SeverityRating(default="critical")

    def test_info_no_cvss_ok(self):
        s = SeverityRating(default="info")
        assert s.cvss_base is None


# ---------------------------------------------------------------------------
# AARFAssessment
# ---------------------------------------------------------------------------

class TestAARF:
    def test_valid_aarf(self):
        a = AARFAssessment(
            autonomy=1.0, tools=0.5, language=0.0, context=1.0,
            non_determinism=0.5, opacity=0.5, persistence=1.0,
            identity=0.0, multi_agent=0.0, self_modification=0.0,
        )
        assert a.autonomy == 1.0

    def test_invalid_aarf_value(self):
        with pytest.raises(ValueError, match="AARF factor"):
            AARFAssessment(
                autonomy=0.7, tools=0.5, language=0.0, context=1.0,
                non_determinism=0.5, opacity=0.5, persistence=1.0,
                identity=0.0, multi_agent=0.0, self_modification=0.0,
            )


# ---------------------------------------------------------------------------
# ReaperCheck metadata validation
# ---------------------------------------------------------------------------

class TestReaperCheckValidation:
    def _make_valid_check(self) -> ReaperCheck:
        check = ReaperCheck()
        check.check_id = "RPR-CONF-999"
        check.name = "Test Check"
        check.description = "A test check."
        check.category = "config"
        check.wedge = 1
        check.tier = "community"
        check.frameworks = ["openclaw"]
        check.check_type = "deterministic"
        check.taxonomy = TaxonomyMapping(
            primary=TaxonomyEntry(framework="owasp_asi", entry_id="ASI01", justification="test")
        )
        check.severity = SeverityRating(default="medium", cvss_base=5.0)
        return check

    def test_valid_check_passes(self):
        check = self._make_valid_check()
        assert check.validate_metadata() == []

    def test_missing_check_id(self):
        check = self._make_valid_check()
        check.check_id = ""
        errors = check.validate_metadata()
        assert any("check_id" in e for e in errors)

    def test_name_too_long(self):
        check = self._make_valid_check()
        check.name = "x" * 81
        errors = check.validate_metadata()
        assert any("80 chars" in e for e in errors)

    def test_unknown_framework(self):
        check = self._make_valid_check()
        check.frameworks = ["nonexistent"]
        errors = check.validate_metadata()
        assert any("unknown framework" in e for e in errors)

    def test_universal_framework_ok(self):
        check = self._make_valid_check()
        check.frameworks = ["universal"]
        assert check.validate_metadata() == []
