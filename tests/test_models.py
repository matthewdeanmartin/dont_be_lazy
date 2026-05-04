"""Tests for the Suppression data model."""

from typing import Any

from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression


def _make(**kwargs):
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


def test_suppression_id_is_set():
    s = _make()
    assert s.id.startswith("DBL")
    assert len(s.id) == 11  # DBL + 8 hex chars


def test_suppression_id_stable():
    s1 = _make()
    s2 = _make()
    assert s1.id == s2.id


def test_fingerprint_stable():
    s = _make()
    assert s.fingerprint() == s.fingerprint()


def test_fingerprint_differs_by_kind():
    s1 = _make(kind="noqa-blanket")
    s2 = _make(kind="noqa-specific")
    assert s1.fingerprint() != s2.fingerprint()


def test_risk_level_ordering():
    assert RiskLevel.low < RiskLevel.medium
    assert RiskLevel.medium < RiskLevel.high
    assert RiskLevel.high < RiskLevel.critical
    assert RiskLevel.low <= RiskLevel.low
    assert RiskLevel.high >= RiskLevel.medium
