"""Tests for baseline command helpers."""

from __future__ import annotations

from dont_be_lazy.commands.baseline_cmd import (
    baseline_first_seen_map,
    check_new_findings,
    create_baseline,
    load_baseline,
    prune_baseline,
    save_baseline,
)
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression


def _suppression(path: str = "src\\mod.py", line: int = 2, text: str = "value = 1  # noqa") -> Suppression:
    return Suppression(
        tool="ruff",
        kind="noqa-blanket",
        pattern="# noqa",
        path=path,
        line=line,
        end_line=line,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=["blanket-ignore"],
        text=text,
    )


def test_baseline_round_trip(tmp_path) -> None:
    finding = _suppression()
    baseline = create_baseline([finding])
    baseline_path = tmp_path / "baseline.json"

    save_baseline(baseline, str(baseline_path))
    loaded = load_baseline(str(baseline_path))

    assert loaded["count"] == 1
    assert baseline_first_seen_map(loaded)[finding.fingerprint()]


def test_check_new_findings_distinguishes_known_and_new() -> None:
    known = _suppression()
    baseline = create_baseline([known])
    new = _suppression(line=8, text="other = 2  # noqa")

    new_findings, known_findings = check_new_findings([known, new], baseline)

    assert new_findings == [new]
    assert known_findings == [known]


def test_prune_baseline_removes_resolved_entries() -> None:
    first = _suppression()
    second = _suppression(line=8, text="other = 2  # noqa")
    baseline = create_baseline([first, second])

    pruned, removed = prune_baseline(baseline, [first])

    assert pruned["count"] == 1
    assert len(removed) == 1
