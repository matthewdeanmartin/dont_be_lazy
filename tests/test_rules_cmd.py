"""Tests for rules command formatting helpers."""

from __future__ import annotations

import json

from dont_be_lazy.commands.rules_cmd import format_rules_list, format_rules_test
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression
from dont_be_lazy.policy import PolicyViolation


def suppression() -> Suppression:
    return Suppression(
        tool="ruff",
        kind="noqa-blanket",
        pattern="# noqa",
        path="src\\mod.py",
        line=2,
        end_line=2,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=["blanket-ignore"],
        text="value = 1  # noqa",
    )


def test_format_rules_list_supports_markdown() -> None:
    output = format_rules_list("markdown")

    assert "| Rule ID | Description |" in output
    assert "DBL001" in output


def test_format_rules_list_supports_json() -> None:
    output = format_rules_list("json")
    data = json.loads(output)
    assert any(r["id"] == "DBL001" for r in data)


def test_format_rules_list_supports_table() -> None:
    output = format_rules_list("table")
    assert "Rule ID" in output
    assert "DBL001" in output


def test_format_rules_test_supports_table() -> None:
    violation = PolicyViolation("DBL001", "Blanket inline suppression", suppression())
    output = format_rules_test([violation], "table")
    assert "1 policy violation(s) found" in output
    assert "DBL001" in output


def test_format_rules_test_long_path() -> None:
    s = suppression()
    s.path = "a" * 60 + "/mod.py"
    violation = PolicyViolation("DBL001", "Blanket inline suppression", s)
    output = format_rules_test([violation], "table")
    assert "..." not in output  # It just slices the last 50 chars, no ellipsis in current implementation
    assert s.path[-50:] in output


def test_format_rules_test_no_violations() -> None:
    output = format_rules_test([], "table")
    assert "No policy violations found" in output
