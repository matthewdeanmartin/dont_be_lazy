"""Tests for owners command helpers."""

from __future__ import annotations

import json

from dont_be_lazy.commands.owners_cmd import attach_owners, format_owners_json, format_owners_table, load_owner_map
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression


def _suppression(line: int = 2, text: str = "value = 1  # noqa") -> Suppression:
    return Suppression(
        tool="ruff",
        kind="noqa-blanket",
        pattern="# noqa",
        path="src\\mod.py",
        line=line,
        end_line=line,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=["blanket-ignore"],
        text=text,
    )


def test_load_owner_map_skips_comments(tmp_path) -> None:
    owner_map_path = tmp_path / "OWNERS"
    owner_map_path.write_text("# comment\njane@example.com team-platform\n", encoding="utf-8")

    assert load_owner_map(str(owner_map_path)) == {"jane@example.com": "team-platform"}


def test_attach_owners_applies_owner_map(monkeypatch) -> None:
    monkeypatch.setattr("dont_be_lazy.git.is_git_repo", lambda root: True)
    monkeypatch.setattr(
        "dont_be_lazy.git.blame_lines",
        lambda path, lines, root: {2: {"author": "Jane", "email": "jane@example.com", "date": "2024-01-01"}},
    )

    findings = attach_owners([_suppression()], "C:\\repo", owner_map={"jane@example.com": "team-platform"})

    assert findings[0].owner == "team-platform"
    assert findings[0].git_author == "Jane"


def test_format_owners_supports_groupings() -> None:
    finding = _suppression()
    finding.git_author = "Jane"
    finding.git_email = "jane@example.com"
    finding.owner = "team-platform"

    by_email = format_owners_table([finding], group_by="email")
    by_team = format_owners_table([finding], group_by="team")
    payload = json.loads(format_owners_json([finding]))

    assert "jane@example.com (1 suppressions)" in by_email
    assert "team-platform (1 suppressions)" in by_team
    assert payload["findings"][0]["owner"] == "team-platform"
