"""Tests for explain command helpers."""

from __future__ import annotations

from dont_be_lazy.commands.explain_cmd import (
    explain_suppression,
    explain_suppression_json,
    find_suppression_by_id,
    find_suppression_by_location,
)
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression


def _suppression() -> Suppression:
    return Suppression(
        tool="mypy",
        kind="type-ignore-specific",
        pattern="# type: ignore[attr-defined]",
        path="src\\mod.py",
        line=42,
        end_line=42,
        scope=ScopeKind.line,
        codes=["attr-defined"],
        reason="legacy import",
        risk=RiskLevel.medium,
        flags=[],
        text="from legacy import thing  # type: ignore[attr-defined]",
    )


def test_explain_text_includes_review_prompts() -> None:
    output = explain_suppression(_suppression())

    assert "Matched: mypy" in output
    assert "Review:" in output
    assert "Can the ignore be code-specific" in output


def test_explain_json_marks_code_specific() -> None:
    payload = explain_suppression_json(_suppression())

    assert payload["finding"]["tool"] == "mypy"
    assert payload["code_specific"] is True
    assert payload["blanket"] is False


def test_find_helpers_locate_suppression() -> None:
    finding = _suppression()
    findings = [finding]

    assert find_suppression_by_id(findings, finding.id) is finding
    assert find_suppression_by_location(findings, "src\\mod.py", 42) is finding
