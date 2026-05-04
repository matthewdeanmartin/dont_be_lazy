"""Tests for hypothesis suppression detection via AST scanner."""

from dont_be_lazy.scanners.python_ast import scan_python_ast


def _scan(source: str):
    return scan_python_ast("test.py", source)


def test_suppress_health_check():
    source = (
        "from hypothesis import HealthCheck, settings\n"
        "@settings(suppress_health_check=[HealthCheck.too_slow])\n"
        "def test_foo(): pass\n"
    )
    findings = _scan(source)
    f = next((s for s in findings if s.tool == "hypothesis" and s.kind == "suppress-health-check"), None)
    assert f is not None


def test_deadline_none():
    source = "from hypothesis import settings\n" "@settings(deadline=None)\n" "def test_foo(): pass\n"
    findings = _scan(source)
    f = next((s for s in findings if s.tool == "hypothesis" and s.kind == "deadline-none"), None)
    assert f is not None


def test_deadline_with_value_not_flagged():
    source = "from hypothesis import settings\n" "@settings(deadline=500)\n" "def test_foo(): pass\n"
    findings = _scan(source)
    hypothesis_findings = [s for s in findings if s.tool == "hypothesis"]
    assert not any(s.kind == "deadline-none" for s in hypothesis_findings)
