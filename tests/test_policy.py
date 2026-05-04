"""Tests for the policy engine (DBL001–DBL015)."""

from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression
from dont_be_lazy.policy import check, check_all, rules_table


def _sup(**kwargs):
    defaults = dict(
        tool="ruff",
        kind="noqa-blanket",
        pattern="# noqa",
        path="src/foo.py",
        line=1,
        end_line=1,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=["blanket-ignore"],
        text="x = 1  # noqa",
    )
    defaults.update(kwargs)
    return Suppression(**defaults)


def test_dbl001_blanket_inline():
    s = _sup(flags=["blanket-ignore"], scope=ScopeKind.line)
    violations = check(s)
    ids = [v.rule_id for v in violations]
    assert "DBL001" in ids


def test_dbl002_file_wide():
    s = _sup(scope=ScopeKind.file, flags=[])
    violations = check(s)
    ids = [v.rule_id for v in violations]
    assert "DBL002" in ids


def test_dbl003_unclosed_block():
    s = _sup(flags=["unclosed-block-suppression"], scope=ScopeKind.block)
    violations = check(s)
    ids = [v.rule_id for v in violations]
    assert "DBL003" in ids


def test_dbl004_no_reason_when_required():
    s = _sup(reason=None, flags=[])
    violations = check(s, policy={"require_reason": True})
    ids = [v.rule_id for v in violations]
    assert "DBL004" in ids


def test_dbl004_not_triggered_when_reason_present():
    s = _sup(reason="needed for legacy compat", flags=[])
    violations = check(s, policy={"require_reason": True})
    ids = [v.rule_id for v in violations]
    assert "DBL004" not in ids


def test_dbl006_security_tool():
    s = _sup(tool="bandit", kind="nosec-blanket", flags=["blanket-ignore"])
    violations = check(s)
    ids = [v.rule_id for v in violations]
    assert "DBL006" in ids


def test_dbl007_type_checker():
    s = _sup(tool="mypy", kind="type-ignore-blanket", flags=["blanket-ignore"])
    violations = check(s)
    ids = [v.rule_id for v in violations]
    assert "DBL007" in ids


def test_dbl008_skipped_test():
    s = _sup(tool="pytest", kind="skip-unconditional", scope=ScopeKind.test, flags=[])
    violations = check(s)
    ids = [v.rule_id for v in violations]
    assert "DBL008" in ids


def test_dbl009_nonstrict_xfail():
    s = _sup(tool="pytest", kind="xfail-nonstrict", scope=ScopeKind.test, flags=[])
    violations = check(s)
    ids = [v.rule_id for v in violations]
    assert "DBL009" in ids


def test_dbl010_config_ignore():
    s = _sup(scope=ScopeKind.config, kind="config-ignore", flags=["config-level"])
    violations = check(s)
    ids = [v.rule_id for v in violations]
    assert "DBL010" in ids


def test_dbl011_config_exclude():
    s = _sup(scope=ScopeKind.config, kind="config-exclude", flags=["config-level"])
    violations = check(s)
    ids = [v.rule_id for v in violations]
    assert "DBL011" in ids


def test_dbl013_unknown_suspicious():
    s = _sup(tool="unknown", kind="suspicious-comment", flags=["suspicious"])
    violations = check(s)
    ids = [v.rule_id for v in violations]
    assert "DBL013" in ids


def test_dbl015_vulnerability():
    s = _sup(tool="safety", kind="ignored-vulnerability", scope=ScopeKind.config, flags=["security"])
    violations = check(s)
    ids = [v.rule_id for v in violations]
    assert "DBL015" in ids


def test_check_all():
    findings = [
        _sup(flags=["blanket-ignore"]),
        _sup(tool="bandit", kind="nosec-blanket", flags=["blanket-ignore"]),
    ]
    violations = check_all(findings)
    assert len(violations) > 0


def test_rules_table():
    table = rules_table()
    ids = [r["id"] for r in table]
    assert "DBL001" in ids
    assert "DBL015" in ids
    assert len(table) == 15
