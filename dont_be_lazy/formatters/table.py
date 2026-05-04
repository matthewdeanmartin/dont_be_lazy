"""Plain-text table formatter."""

from __future__ import annotations

import os

from dont_be_lazy.models import Suppression

_HEADERS = ("Risk", "Tool", "Scope", "Path", "Line", "Suppression")
_COL_SEP = "  "


def format_table(findings: list[Suppression], no_color: bool = False) -> str:
    """Format findings as an aligned plain-text table."""
    colors = {
        "critical": "\033[91m",
        "high": "\033[93m",
        "medium": "\033[94m",
        "low": "\033[92m",
        "reset": "\033[0m",
    }

    rows = []
    for s in findings:
        rows.append(
            (
                s.risk.value.upper(),
                s.tool,
                s.scope.value,
                os.path.relpath(s.path) if os.path.isabs(s.path) else s.path,
                str(s.line),
                (s.text or s.pattern)[:80],
            )
        )

    if not rows:
        return "No suppressions found.\n"

    widths = [len(h) for h in _HEADERS]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(row: tuple[str, ...]) -> str:
        return _COL_SEP.join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    lines = [
        fmt_row(_HEADERS),
        _COL_SEP.join("-" * w for w in widths),
    ]
    for row, s in zip(rows, findings, strict=True):
        line = fmt_row(row)
        if not no_color:
            color = colors.get(s.risk.value, "")
            reset = colors["reset"]
            line = f"{color}{line}{reset}"
        lines.append(line)
        if s.context:
            lines.extend(f"    {ctx}" for ctx in s.context)

    return "\n".join(lines) + "\n"
