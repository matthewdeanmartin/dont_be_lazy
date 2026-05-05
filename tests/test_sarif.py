"""Tests for SARIF formatter."""

import json
from typing import Any

from dont_be_lazy.formatters.sarif import format_sarif
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression


def sup(**kwargs):
    defaults: dict[str, Any] = {
        "tool": "ruff",
        "kind": "noqa-blanket",
        "pattern": "# noqa",
        "path": "src/foo.py",
        "line": 10,
        "end_line": 10,
        "scope": ScopeKind.line,
        "codes": [],
        "reason": None,
        "risk": RiskLevel.high,
        "flags": [],
        "text": "x = 1  # noqa",
    }
    defaults.update(kwargs)
    return Suppression(**defaults)


def test_sarif_schema_version():
    out = format_sarif([])
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc


def test_sarif_has_runs():
    out = format_sarif([sup()])
    doc = json.loads(out)
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert "tool" in run
    assert run["tool"]["driver"]["name"] == "dont_be_lazy"


def test_sarif_results_populated():
    out = format_sarif([sup(), sup(tool="mypy", kind="type-ignore-blanket")])
    doc = json.loads(out)
    results = doc["runs"][0]["results"]
    assert len(results) == 2


def test_sarif_result_structure():
    out = format_sarif([sup()])
    doc = json.loads(out)
    r = doc["runs"][0]["results"][0]
    assert "ruleId" in r
    assert "level" in r
    assert "locations" in r
    loc = r["locations"][0]["physicalLocation"]
    assert "artifactLocation" in loc
    assert "region" in loc
    assert loc["region"]["startLine"] == 10


def test_sarif_severity_mapping():
    findings = [
        sup(risk=RiskLevel.low),
        sup(risk=RiskLevel.medium),
        sup(risk=RiskLevel.high),
        sup(risk=RiskLevel.critical),
    ]
    out = format_sarif(findings)
    doc = json.loads(out)
    levels = [r["level"] for r in doc["runs"][0]["results"]]
    assert "note" in levels
    assert "warning" in levels
    assert levels.count("error") == 2


def test_sarif_empty_findings():
    out = format_sarif([])
    doc = json.loads(out)
    assert doc["runs"][0]["results"] == []


def test_sarif_rules_deduped():
    # Two findings of same tool/kind → one rule entry
    findings = [sup(), sup(line=20)]
    out = format_sarif(findings)
    doc = json.loads(out)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert len(rule_ids) == len(set(rule_ids))
