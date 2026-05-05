"""Tests for custom suppression pattern support."""

from dont_be_lazy.custom_patterns import CustomPatternScanner
from dont_be_lazy.models import RiskLevel


def test_custom_pattern_matches():
    config = {
        "our-linter": {
            "patterns": [r"#\s*our-linter:\s*ignore(?:\[(?P<codes>[^\]]+)\])?"],
            "scope": "line",
            "risk": "medium",
        }
    }
    scanner = CustomPatternScanner(config)
    source = "x = 1  # our-linter: ignore[RULE-1]\n"
    findings = scanner.scan("test.py", source)
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "our-linter"
    assert "RULE-1" in f.codes
    assert "custom-pattern" in f.flags


def test_custom_pattern_no_codes():
    config = {
        "our-linter": {
            "patterns": [r"#\s*our-linter:\s*ignore"],
            "scope": "line",
            "risk": "high",
        }
    }
    scanner = CustomPatternScanner(config)
    source = "x = 1  # our-linter: ignore\n"
    findings = scanner.scan("test.py", source)
    assert len(findings) == 1
    assert findings[0].risk == RiskLevel.high


def test_custom_pattern_skips_strings():
    config = {
        "our-linter": {
            "patterns": [r"#\s*our-linter:\s*ignore"],
            "scope": "line",
            "risk": "medium",
        }
    }
    scanner = CustomPatternScanner(config)
    source = 'text = "# our-linter: ignore"\n'
    findings = scanner.scan("test.py", source)
    assert not findings, "Should not match inside string literals"


def test_custom_pattern_list_form():
    config = {"tool-x": [r"#\s*tool-x:\s*off"]}
    scanner = CustomPatternScanner(config)
    source = "# tool-x: off\n"
    findings = scanner.scan("test.py", source)
    assert len(findings) == 1
    assert findings[0].tool == "tool-x"


def test_invalid_regex_skipped():
    config = {
        "bad-tool": {
            "patterns": [r"[invalid regex ("],
            "scope": "line",
            "risk": "medium",
        }
    }
    scanner = CustomPatternScanner(config)
    assert not scanner.compiled


def test_empty_config():
    scanner = CustomPatternScanner({})
    findings = scanner.scan("test.py", "x = 1  # noqa\n")
    assert not findings
