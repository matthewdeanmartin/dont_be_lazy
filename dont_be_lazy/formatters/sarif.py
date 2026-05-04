"""SARIF 2.1.0 formatter for dont_be_lazy findings."""

from __future__ import annotations

import datetime
import json
import os
from typing import Any

from dont_be_lazy.__about__ import __version__
from dont_be_lazy.models import RiskLevel, Suppression

_SEVERITY = {
    RiskLevel.low: "note",
    RiskLevel.medium: "warning",
    RiskLevel.high: "error",
    RiskLevel.critical: "error",
}


def format_sarif(findings: list[Suppression], root: str = "") -> str:
    """Format findings as a SARIF 2.1.0 document."""
    rules: dict[str, dict[str, Any]] = {}
    results = []

    for s in findings:
        rule_id = f"{s.tool}/{s.kind}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": s.kind,
                "shortDescription": {"text": f"{s.tool} {s.kind} suppression"},
                "defaultConfiguration": {"level": _SEVERITY[s.risk]},
                "properties": {"tags": [s.tool, s.kind]},
            }

        rel_path = os.path.relpath(s.path, root) if root and os.path.isabs(s.path) else s.path
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEVERITY[s.risk],
            "message": {"text": s.text or s.pattern},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": rel_path.replace("\\", "/")},
                        "region": {"startLine": max(1, s.line)},
                    }
                }
            ],
            "properties": {
                "tool": s.tool,
                "kind": s.kind,
                "scope": s.scope.value,
                "risk": s.risk.value,
                "codes": s.codes,
                "flags": s.flags,
                "id": s.id,
            },
        }
        if s.end_line and s.end_line != s.line:
            result["locations"][0]["physicalLocation"]["region"]["endLine"] = s.end_line
        results.append(result)

    doc = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dont_be_lazy",
                        "version": __version__,
                        "informationUri": "https://github.com/matthewdeanmartin/dont_be_lazy",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": datetime.datetime.utcnow().isoformat() + "Z",
                    }
                ],
            }
        ],
    }
    return json.dumps(doc, indent=2)
