"""JSON formatter."""

from __future__ import annotations

import datetime
import json
from typing import Any

from dont_be_lazy.models import Suppression


def _sup_to_dict(s: Suppression) -> dict[str, Any]:
    """Serialize one suppression to a JSON-safe dictionary."""
    doc: dict[str, Any] = {
        "id": s.id,
        "tool": s.tool,
        "kind": s.kind,
        "pattern": s.pattern,
        "path": s.path,
        "line": s.line,
        "end_line": s.end_line,
        "scope": s.scope.value,
        "codes": s.codes,
        "reason": s.reason,
        "risk": s.risk.value,
        "flags": s.flags,
        "text": s.text,
    }
    age: dict[str, Any] = {}
    if s.first_seen:
        age["first_seen"] = s.first_seen
    if s.git_date:
        age["last_modified"] = s.git_date
    if s.git_author:
        age["git_author"] = s.git_author
    if age:
        doc["age"] = age
    if s.git_email:
        doc["git_email"] = s.git_email
    if s.owner:
        doc["owner"] = s.owner
    if s.context:
        doc["context"] = s.context
    return doc


def format_json(findings: list[Suppression], root: str = "") -> str:
    """Format findings as a single JSON document."""
    by_tool: dict[str, int] = {}
    for s in findings:
        by_tool[s.tool] = by_tool.get(s.tool, 0) + 1

    doc = {
        "version": "1.0",
        "root": root,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "summary": {
            "total": len(findings),
            "by_tool": by_tool,
        },
        "findings": [_sup_to_dict(s) for s in findings],
    }
    return json.dumps(doc, indent=2)


def format_jsonl(findings: list[Suppression]) -> str:
    """Format findings as newline-delimited JSON."""
    return "\n".join(json.dumps(_sup_to_dict(s)) for s in findings) + ("\n" if findings else "")
