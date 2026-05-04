"""Tests for risk scoring."""

from typing import Any

from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression
from dont_be_lazy.risk import score


def _sup(**kwargs):
    defaults: dict[str, Any] = {
        "tool": "ruff",
        "kind": "noqa-blanket",
        "pattern": "# noqa",
        "path": "src/foo.py",
        "line": 1,
        "end_line": 1,
        "scope": ScopeKind.line,
        "codes": [],
        "reason": None,
        "risk": RiskLevel.medium,
        "flags": [],
        "text": "x = 1  # noqa",
    }
    defaults.update(kwargs)
    return Suppression(**defaults)


def test_nosec_blanket_is_critical():
    s = _sup(tool="bandit", kind="nosec-blanket")
    assert score(s) == RiskLevel.critical


def test_type_ignore_specific_medium():
    s = _sup(tool="mypy", kind="type-ignore-specific", codes=["attr-defined"])
    result = score(s)
    assert result in (RiskLevel.low, RiskLevel.medium)


def test_no_codes_bumps_risk():
    s1 = _sup(tool="mypy", kind="type-ignore-blanket", codes=[])
    s2 = _sup(tool="mypy", kind="type-ignore-specific", codes=["attr-defined"])
    assert score(s1) >= score(s2)


def test_file_scope_bumps_risk():
    s_line = _sup(tool="mypy", kind="type-ignore-blanket", scope=ScopeKind.line, codes=[])
    s_file = _sup(tool="mypy", kind="file-ignore-errors", scope=ScopeKind.file, codes=[])
    assert score(s_file) >= score(s_line)


def test_fmt_skip_is_low():
    s = _sup(tool="black", kind="fmt-skip", codes=[])
    assert score(s) == RiskLevel.low
