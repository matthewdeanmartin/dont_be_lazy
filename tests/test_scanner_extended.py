"""Tests for extended comment patterns (Phase 2)."""

import os

from dont_be_lazy.models import RiskLevel
from dont_be_lazy.scanners.python_comments import scan_python_comments

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_extended.py")


def _scan(source: str):
    return scan_python_comments("test.py", source)


def test_pytype_disable_block():
    source = "# pytype: disable=attribute-error\nx = 1\n# pytype: enable=attribute-error\n"
    findings = _scan(source)
    f = next((s for s in findings if s.tool == "pytype"), None)
    assert f is not None
    assert "attribute-error" in f.codes
    assert f.end_line == 3


def test_pytype_disable_unclosed():
    source = "# pytype: disable=attribute-error\nx = 1\n"
    findings = _scan(source)
    f = next((s for s in findings if s.tool == "pytype"), None)
    assert f is not None
    assert "unclosed-block-suppression" in f.flags


def test_ty_ignore_blanket():
    findings = _scan("x = 1  # ty: ignore\n")
    f = next((s for s in findings if s.tool == "ty"), None)
    assert f is not None
    assert f.kind == "ignore-blanket"


def test_ty_ignore_specific():
    findings = _scan("x = 1  # ty: ignore[rule-name]\n")
    f = next((s for s in findings if s.tool == "ty"), None)
    assert f is not None
    assert f.kind == "ignore-specific"
    assert "rule-name" in f.codes


def test_nosemgrep_blanket():
    findings = _scan("x = 1  # nosemgrep\n")
    f = next((s for s in findings if s.tool == "semgrep"), None)
    assert f is not None
    assert f.kind == "nosemgrep-blanket"

    assert f.risk == RiskLevel.critical


def test_nosemgrep_specific():
    findings = _scan("x = 1  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use\n")
    f = next((s for s in findings if s.tool == "semgrep"), None)
    assert f is not None
    assert f.kind == "nosemgrep-specific"
    assert len(f.codes) == 1


def test_allowlist_secret():
    findings = _scan('password = "abc"  # pragma: allowlist secret\n')
    f = next((s for s in findings if s.tool == "secrets"), None)
    assert f is not None
    assert f.kind == "allowlist-secret"


def test_whitelist_secret():
    findings = _scan('secret = "abc"  # pragma: whitelist secret\n')
    f = next((s for s in findings if s.tool == "secrets"), None)
    assert f is not None


def test_autopep8_off_on():
    source = "# autopep8: off\nx = 1\n# autopep8: on\n"
    findings = _scan(source)
    f = next((s for s in findings if s.tool == "autopep8"), None)
    assert f is not None
    assert f.end_line == 3


def test_autopep8_unclosed():
    source = "# autopep8: off\nx = 1\n"
    findings = _scan(source)
    f = next((s for s in findings if s.tool == "autopep8"), None)
    assert f is not None
    assert "unclosed-block-suppression" in f.flags


def test_yapf_disable_enable():
    source = "# yapf: disable\nx = {1:2}\n# yapf: enable\n"
    findings = _scan(source)
    f = next((s for s in findings if s.tool == "yapf"), None)
    assert f is not None
    assert f.end_line == 3


def test_nosonar():
    findings = _scan("x = 1  # NOSONAR\n")
    f = next((s for s in findings if s.tool == "sonar"), None)
    assert f is not None
    assert f.kind == "nosonar"


def test_suspicious_comment():
    findings = _scan("x = 1  # ignore this\n")
    f = next((s for s in findings if s.tool == "unknown"), None)
    assert f is not None
    assert "suspicious" in f.flags


def test_fixture_extended():
    with open(FIXTURE, encoding="utf-8") as f:
        source = f.read()
    findings = scan_python_comments(FIXTURE, source)
    tools = {s.tool for s in findings}
    assert "pytype" in tools
    assert "ty" in tools
    assert "semgrep" in tools
    assert "secrets" in tools
    assert "autopep8" in tools
    assert "yapf" in tools
    assert "sonar" in tools
