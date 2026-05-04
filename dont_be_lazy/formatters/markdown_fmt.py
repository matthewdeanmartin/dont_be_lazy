"""Markdown formatter."""

from __future__ import annotations

import datetime
import os

from dont_be_lazy.models import RiskLevel, Suppression


def format_markdown(findings: list[Suppression], root: str = "") -> str:
    """Format findings as a compact Markdown report."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    lines = [
        "# dont_be_lazy report",
        "",
        f"Generated: {now}",
        "",
        "## Summary",
        "",
    ]

    by_tool: dict[str, dict[str, int]] = {}
    for s in findings:
        t = by_tool.setdefault(s.tool, {"count": 0, "high": 0, "critical": 0, "no_reason": 0})
        t["count"] += 1
        if s.risk in (RiskLevel.high, RiskLevel.critical):
            t["high"] += 1
        if s.risk == RiskLevel.critical:
            t["critical"] += 1
        if not s.reason:
            t["no_reason"] += 1

    lines.append("| Tool | Count | High | Critical | No reason |")
    lines.append("|---|---:|---:|---:|---:|")
    for tool, stats in sorted(by_tool.items()):
        lines.append(f"| {tool} | {stats['count']} | {stats['high']} | {stats['critical']} | {stats['no_reason']} |")
    lines.append("")

    if findings:
        lines.append("## Highest priority")
        lines.append("")
        critical_first = sorted(findings, key=lambda s: list(RiskLevel).index(s.risk), reverse=True)
        for i, s in enumerate(critical_first[:10], 1):
            rel = os.path.relpath(s.path, root) if root and os.path.isabs(s.path) else s.path
            lines.append(f"{i}. `{rel}:{s.line}` — `{s.text[:60]}`")
        lines.append("")

    return "\n".join(lines)
