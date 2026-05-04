
import pytest
from dont_be_lazy.models import Suppression, RiskLevel, ScopeKind
from dont_be_lazy.policy import check, check_all

def test_policy_blanket():
    s = Suppression(
        tool="ruff",
        kind="noqa-blanket",
        pattern="# noqa",
        path="test.py",
        line=1,
        end_line=1,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=["blanket-ignore"],
        text="# noqa"
    )
    violations = check(s)
    assert any(v.rule_id == "DBL001" for v in violations)

def test_policy_file_wide():
    s = Suppression(
        tool="pylint",
        kind="file-noqa",
        pattern="# ruff: noqa",
        path="test.py",
        line=1,
        end_line=1,
        scope=ScopeKind.file,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=["file-wide"],
        text="# ruff: noqa"
    )
    violations = check(s)
    assert any(v.rule_id == "DBL002" for v in violations)

def test_policy_security():
    s = Suppression(
        tool="bandit",
        kind="nosec-blanket",
        pattern="# nosec",
        path="test.py",
        line=1,
        end_line=1,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.critical,
        flags=["blanket-ignore"],
        text="# nosec"
    )
    violations = check(s)
    assert any(v.rule_id == "DBL006" for v in violations)
    # Also blanket
    assert any(v.rule_id == "DBL001" for v in violations)

def test_policy_skipped_test():
    s = Suppression(
        tool="pytest",
        kind="skip-unconditional",
        pattern="skip-unconditional",
        path="test_one.py",
        line=1,
        end_line=1,
        scope=ScopeKind.test,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=["no-reason"],
        text="@pytest.mark.skip"
    )
    violations = check(s)
    assert any(v.rule_id == "DBL008" for v in violations)

def test_policy_require_reason():
    s = Suppression(
        tool="mypy",
        kind="type-ignore-specific",
        pattern="# type: ignore[attr-defined]",
        path="test.py",
        line=1,
        end_line=1,
        scope=ScopeKind.line,
        codes=["attr-defined"],
        reason=None,
        risk=RiskLevel.medium,
        flags=[],
        text="# type: ignore[attr-defined]"
    )
    # Default policy: no reason required
    assert not any(v.rule_id == "DBL004" for v in check(s))
    
    # Custom policy: require reason
    policy = {"require_reason": True}
    violations = check(s, policy)
    assert any(v.rule_id == "DBL004" for v in violations)

def test_check_all():
    s1 = Suppression(
        tool="ruff", kind="noqa-blanket", pattern="# noqa", path="a.py", line=1, end_line=1,
        scope=ScopeKind.line, codes=[], reason=None, risk=RiskLevel.high, flags=["blanket-ignore"], text="# noqa"
    )
    s2 = Suppression(
        tool="bandit", kind="nosec-blanket", pattern="# nosec", path="b.py", line=1, end_line=1,
        scope=ScopeKind.line, codes=[], reason=None, risk=RiskLevel.critical, flags=["blanket-ignore"], text="# nosec"
    )
    violations = check_all([s1, s2])
    # DBL001 for both, DBL006 for bandit
    assert len(violations) >= 3
    rule_ids = {v.rule_id for v in violations}
    assert "DBL001" in rule_ids
    assert "DBL006" in rule_ids
