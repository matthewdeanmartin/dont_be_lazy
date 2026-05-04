"""Tests for rules command formatting helpers."""

from __future__ import annotations

import json

from dont_be_lazy.commands.rules_cmd import format_rules_list, format_rules_test
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression
from dont_be_lazy.policy import PolicyViolation


def _suppression() -> Suppression:
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


def test_format_rules_test_supports_json() -> None:
    violation = PolicyViolation("DBL001", "Blanket inline suppression", _suppression())

    payload = json.loads(format_rules_test([violation], "json"))

    assert payload[0]["rule_id"] == "DBL001"
    assert payload[0]["suppression_id"].startswith("DBL")
