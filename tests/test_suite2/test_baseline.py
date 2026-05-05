from dont_be_lazy.commands.baseline_cmd import check_new_findings, create_baseline, prune_baseline
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression


def test_baseline_lifecycle():
    s1 = Suppression(
        tool="ruff",
        kind="noqa-blanket",
        pattern="# noqa",
        path="a.py",
        line=1,
        end_line=1,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=["blanket-ignore"],
        text="# noqa",
    )
    s2 = Suppression(
        tool="bandit",
        kind="nosec-blanket",
        pattern="# nosec",
        path="b.py",
        line=1,
        end_line=1,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.critical,
        flags=["blanket-ignore"],
        text="# nosec",
    )

    # 1. Create baseline
    baseline = create_baseline([s1])
    assert baseline["count"] == 1
    assert baseline["entries"][0]["tool"] == "ruff"

    # 2. Check new findings
    new, known = check_new_findings([s1, s2], baseline)
    assert len(new) == 1
    assert new[0].tool == "bandit"
    assert len(known) == 1
    assert known[0].tool == "ruff"

    # 3. Prune baseline (s2 is not in baseline, but we only have s2 now)
    pruned, removed = prune_baseline(baseline, [s2])
    assert pruned["count"] == 0
    assert len(removed) == 1
    assert removed[0]["tool"] == "ruff"


def test_baseline_fingerprint_stability():
    # Suppression with same content but different line should have different fingerprint?
    # Let's check model.py fingerprint logic
    s1 = Suppression(
        tool="ruff",
        kind="noqa-blanket",
        pattern="# noqa",
        path="a.py",
        line=1,
        end_line=1,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=["blanket-ignore"],
        text="# noqa",
    )
    s2 = Suppression(
        tool="ruff",
        kind="noqa-blanket",
        pattern="# noqa",
        path="a.py",
        line=10,
        end_line=10,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=["blanket-ignore"],
        text="# noqa",
    )
    # The fingerprint uses path, kind, codes, hash of text, and text.
    # It does NOT use line number, so moving a suppression doesn't break baseline.
    assert s1.fingerprint() == s2.fingerprint()

    # But changing path should change fingerprint
    s3 = Suppression(
        tool="ruff",
        kind="noqa-blanket",
        pattern="# noqa",
        path="b.py",
        line=1,
        end_line=1,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=["blanket-ignore"],
        text="# noqa",
    )
    assert s1.fingerprint() != s3.fingerprint()
