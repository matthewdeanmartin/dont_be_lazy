"""Tests for the stale command helpers."""

from __future__ import annotations

import json
from typing import Any

from dont_be_lazy.commands.stale_cmd import attach_blame, filter_stale, format_stale_json, format_stale_table, parse_age
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression


def suppression(**kwargs) -> Suppression:
    defaults: dict[str, Any] = {
        "tool": "ruff",
        "kind": "noqa-blanket",
        "pattern": "# noqa",
        "path": "src\\mod.py",
        "line": 2,
        "end_line": 2,
        "scope": ScopeKind.line,
        "codes": [],
        "reason": None,
        "risk": RiskLevel.high,
        "flags": ["blanket-ignore"],
        "text": "value = 1  # noqa",
    }
    defaults.update(kwargs)
    return Suppression(**defaults)


def test_parse_age_supports_days_months_and_years() -> None:
    assert parse_age("10") == 10
    assert parse_age("6m") == 180
    assert parse_age("1y") == 365


def test_attach_blame_prefers_baseline(monkeypatch) -> None:
    finding = suppression()
    baseline = {finding.fingerprint(): "2023-01-01"}

    annotated = attach_blame([finding], "C:\\repo", baseline=baseline)

    assert annotated[0].first_seen == "2023-01-01"


def test_attach_blame_uses_git_blame_when_requested(monkeypatch) -> None:
    monkeypatch.setattr("dont_be_lazy.git.is_git_repo", lambda root: True)
    monkeypatch.setattr(
        "dont_be_lazy.git.blame_line",
        lambda path, line, root: {"author": "Jane", "email": "jane@example.com", "date": "2024-01-01"},
    )
    monkeypatch.setattr("dont_be_lazy.git.first_seen_by_log", lambda path, text, root: None)

    finding = attach_blame([suppression()], "C:\\repo", with_git_blame=True)[0]

    assert finding.git_author == "Jane"
    assert finding.first_seen == "2024-01-01"


def test_filter_stale_excludes_unknown_when_requested() -> None:
    old = suppression()
    old.first_seen = "2023-01-01"
    unknown = suppression(line=4, text="other = 2  # noqa")

    stale = filter_stale([old, unknown], 180, include_unknown=False)

    assert stale == [old]


def test_format_stale_outputs_owner_and_json() -> None:
    finding = suppression()
    finding.first_seen = "2023-01-01"
    finding.owner = "team-qa"

    table = format_stale_table([finding], group_by="owner")
    payload = json.loads(format_stale_json([finding]))

    assert "[team-qa]" in table
    assert payload["findings"][0]["age_date"] == "2023-01-01"
