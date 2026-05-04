"""stale subcommand: find suppressions older than a threshold."""

from __future__ import annotations

import collections
import json
import re
from datetime import date

from dont_be_lazy import git
from dont_be_lazy.formatters.json_fmt import _sup_to_dict
from dont_be_lazy.models import Suppression


def parse_age(age_str: str) -> int:
    """Parse age string like '180d', '6m', '1y' into days."""
    m = re.fullmatch(r"(\d+)([dmy]?)", age_str.strip().lower())
    if not m:
        raise ValueError(f"Cannot parse age: {age_str!r}")
    n, unit = int(m.group(1)), m.group(2) or "d"
    if unit == "d":
        return n
    if unit == "m":
        return n * 30
    return n * 365


def age_in_days(date_str: str) -> int:
    """Return days since date_str (YYYY-MM-DD)."""
    try:
        d = date.fromisoformat(date_str)
        return (date.today() - d).days
    except ValueError:
        return 0


def attach_blame(
    findings: list[Suppression],
    root: str,
    baseline: dict[str, str] | None = None,
    with_git_blame: bool = False,
    with_git_history: bool = False,
) -> list[Suppression]:
    """
    Attach age-related metadata to each finding and return the same list.

    Priority: baseline first_seen > git log -S > git blame > None.
    """
    git_available = git.is_git_repo(root)

    for s in findings:
        date_str: str | None = None

        # 1. Baseline first_seen
        if baseline and s.fingerprint() in baseline:
            date_str = baseline[s.fingerprint()]
            s.first_seen = date_str

        # 2. git log -S
        if date_str is None and with_git_history and git_available:
            date_str = git.first_seen_by_log(s.path, s.text.strip(), root)
            s.first_seen = date_str

        # 3. git blame
        if date_str is None and with_git_blame and git_available:
            info = git.blame_line(s.path, s.line, root)
            if info:
                s.git_author = info.get("author")
                s.git_email = info.get("email")
                s.git_date = info.get("date")
                s.owner = s.owner or s.git_author
                date_str = s.git_date

        if date_str and not s.first_seen:
            s.first_seen = date_str

    return findings


def filter_stale(
    findings: list[Suppression],
    older_than_days: int,
    include_unknown: bool = True,
) -> list[Suppression]:
    """Keep only entries with a known date older than threshold, or unknown dates."""
    return [
        s
        for s in findings
        if (s.first_seen is None and include_unknown)
        or (s.first_seen is not None and age_in_days(s.first_seen) >= older_than_days)
    ]


def format_stale_table(
    findings: list[Suppression],
    group_by: str = "tool",
) -> str:
    """Format stale findings as a plain-text report."""
    lines = ["Stale suppressions", ""]
    header = f"{'Age':>5}  {'Risk':<8}  {'Tool':<12}  {'Path':40}  {'Line':>5}  Text"
    lines.append(header)
    lines.append("-" * len(header))

    groups: dict[str, list[Suppression]] = collections.defaultdict(list)
    for s in findings:
        if group_by == "risk":
            key = s.risk.value
        elif group_by == "owner":
            key = s.owner or s.git_author or "unknown"
        else:
            key = getattr(s, group_by, s.tool)
        groups[str(key)].append(s)

    for group_key in sorted(groups):
        lines.append(f"\n[{group_key}]")
        for s in sorted(groups[group_key], key=lambda item: item.path):
            age = f"{age_in_days(s.first_seen)}d" if s.first_seen else "?"
            path_short = s.path[-38:] if len(s.path) > 40 else s.path
            text_short = s.text.strip()[:60]
            lines.append(f"{age:>5}  {s.risk.value:<8}  {s.tool:<12}  {path_short:<40}  {s.line:>5}  {text_short}")

    return "\n".join(lines) + "\n"


def format_stale_json(findings: list[Suppression]) -> str:
    """Format stale findings as JSON."""
    items = []
    for s in findings:
        obj = _sup_to_dict(s)
        obj["age_date"] = s.first_seen
        obj["age_days"] = age_in_days(s.first_seen) if s.first_seen else None
        items.append(obj)
    return json.dumps({"findings": items}, indent=2)
