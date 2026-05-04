"""rules subcommand: list and test active policy rules."""

from __future__ import annotations

import json

from dont_be_lazy.policy import PolicyViolation, rules_table


def format_rules_list(fmt: str = "table") -> str:
    rules = rules_table()
    if fmt == "json":
        return json.dumps(rules, indent=2)
    if fmt == "markdown":
        lines = ["| Rule ID | Description |", "|---|---|"]
        for r in rules:
            lines.append(f"| {r['id']} | {r['description']} |")
        return "\n".join(lines) + "\n"
    # table
    lines = [f"{'Rule ID':<10}  Description"]
    lines.append("-" * 60)
    for r in rules:
        lines.append(f"{r['id']:<10}  {r['description']}")
    return "\n".join(lines) + "\n"


def format_rules_test(
    violations: list[PolicyViolation],
    fmt: str = "table",
) -> str:
    if fmt == "json":
        return json.dumps(
            [
                {
                    "rule_id": v.rule_id,
                    "message": v.message,
                    "suppression_id": v.suppression.id,
                    "path": v.suppression.path,
                    "line": v.suppression.line,
                    "tool": v.suppression.tool,
                    "kind": v.suppression.kind,
                }
                for v in violations
            ],
            indent=2,
        )

    if not violations:
        return "No policy violations found.\n"

    lines = [f"{len(violations)} policy violation(s) found:\n"]
    for v in violations:
        path_short = v.suppression.path[-50:] if len(v.suppression.path) > 50 else v.suppression.path
        lines.append(f"  {v.rule_id}  {path_short}:{v.suppression.line}  {v.message}")
    return "\n".join(lines) + "\n"
