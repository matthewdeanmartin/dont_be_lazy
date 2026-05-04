"""baseline subcommand: create/check/prune baseline of accepted suppressions."""

from __future__ import annotations

import json
from datetime import date
from typing import Any, cast

from dont_be_lazy.formatters.json_fmt import _sup_to_dict
from dont_be_lazy.models import Suppression

_SCHEMA_VERSION = "1"


def _baseline_entry(s: Suppression) -> dict[str, Any]:
    """Build the persisted baseline entry for one suppression."""
    return {
        "id": s.id,
        "fingerprint": s.fingerprint(),
        "tool": s.tool,
        "kind": s.kind,
        "path": s.path,
        "line": s.line,
        "codes": s.codes,
        "text": s.text.strip()[:120],
        "risk": s.risk.value,
        "first_seen": date.today().isoformat(),
    }


def create_baseline(findings: list[Suppression]) -> dict[str, Any]:
    """Build baseline dict from current findings."""
    return {
        "version": _SCHEMA_VERSION,
        "created_at": date.today().isoformat(),
        "count": len(findings),
        "entries": [_baseline_entry(s) for s in findings],
    }


def save_baseline(baseline: dict[str, Any], output_path: str) -> None:
    """Write a baseline document to disk."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)
        f.write("\n")


def load_baseline(path: str) -> dict[str, Any]:
    """Load a baseline document from disk."""
    with open(path, encoding="utf-8") as f:
        return cast(dict[str, Any], json.load(f))


def baseline_fingerprints(baseline: dict[str, Any]) -> set[str]:
    """Return the fingerprints present in a baseline document."""
    return {e["fingerprint"] for e in baseline.get("entries", [])}


def baseline_first_seen_map(baseline: dict[str, Any]) -> dict[str, str]:
    """Return {fingerprint: first_seen_date}."""
    return {e["fingerprint"]: e.get("first_seen", "") for e in baseline.get("entries", [])}


def check_new_findings(
    findings: list[Suppression],
    baseline: dict[str, Any],
) -> tuple[list[Suppression], list[Suppression]]:
    """
    Return (new_findings, known_findings).

    new_findings: suppressions NOT in baseline.
    known_findings: suppressions present in baseline.
    """
    fps = baseline_fingerprints(baseline)
    new = [s for s in findings if s.fingerprint() not in fps]
    known = [s for s in findings if s.fingerprint() in fps]
    return new, known


def prune_baseline(
    baseline: dict[str, Any],
    current_findings: list[Suppression],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Remove baseline entries whose fingerprints no longer appear in current findings.

    Returns (pruned_baseline, removed_entries).
    """
    current_fps = {s.fingerprint() for s in current_findings}
    kept = [e for e in baseline.get("entries", []) if e["fingerprint"] in current_fps]
    removed = [e for e in baseline.get("entries", []) if e["fingerprint"] not in current_fps]
    pruned = dict(baseline)
    pruned["entries"] = kept
    pruned["count"] = len(kept)
    return pruned, removed


def format_check_result(
    new_findings: list[Suppression],
    known_count: int,
    fmt: str = "table",
) -> str:
    """Format the result of a baseline check command."""
    if fmt == "json":
        return json.dumps(
            {
                "new_count": len(new_findings),
                "known_count": known_count,
                "new_findings": [_sup_to_dict(s) for s in new_findings],
            },
            indent=2,
        )

    lines = [f"Baseline check: {len(new_findings)} new, {known_count} known\n"]
    if new_findings:
        lines.append("New suppressions not in baseline:")
        for s in new_findings:
            path_short = s.path[-50:] if len(s.path) > 50 else s.path
            lines.append(f"  {s.risk.value:<8} {s.tool:<12} {path_short}:{s.line} — {s.text.strip()[:60]}")
    return "\n".join(lines) + "\n"
