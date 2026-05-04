"""Tests for output formatters."""

import json

from dont_be_lazy.formatters.json_fmt import format_json, format_jsonl
from dont_be_lazy.formatters.markdown_fmt import format_markdown
from dont_be_lazy.formatters.table import format_table
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression


def _sup(**kwargs):
    defaults = dict(
        tool="ruff",
        kind="noqa-blanket",
        pattern="# noqa",
        path="src/foo.py",
        line=10,
        end_line=10,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.high,
        flags=[],
        text="x = 1  # noqa",
    )
    defaults.update(kwargs)
    return Suppression(**defaults)


def test_table_empty():
    out = format_table([])
    assert "No suppressions" in out


def test_table_has_columns():
    out = format_table([_sup()], no_color=True)
    assert "Risk" in out
    assert "Tool" in out
    assert "ruff" in out


def test_json_schema():
    out = format_json([_sup()])
    doc = json.loads(out)
    assert doc["version"] == "1.0"
    assert "findings" in doc
    assert doc["summary"]["total"] == 1
    assert doc["summary"]["by_tool"]["ruff"] == 1
    finding = doc["findings"][0]
    assert "id" in finding
    assert finding["tool"] == "ruff"
    assert finding["risk"] == "high"


def test_jsonl():
    sups = [_sup(), _sup(tool="mypy", kind="type-ignore-blanket")]
    out = format_jsonl(sups)
    lines = [l for l in out.splitlines() if l]
    assert len(lines) == 2
    assert json.loads(lines[0])["tool"] == "ruff"


def test_markdown_has_summary_table():
    out = format_markdown([_sup(), _sup(tool="mypy")])
    assert "## Summary" in out
    assert "ruff" in out
    assert "mypy" in out


def test_markdown_has_highest_priority():
    out = format_markdown([_sup(risk=RiskLevel.critical)])
    assert "## Highest priority" in out
