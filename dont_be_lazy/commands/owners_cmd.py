"""owners subcommand: group suppressions by git blame author."""

from __future__ import annotations

import collections
import json

from dont_be_lazy.models import Suppression


def load_owner_map(path: str) -> dict[str, str]:
    """Load a simple CODEOWNERS-style map: email/pattern -> team/owner name."""
    owner_map: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    owner_map[parts[0]] = parts[1]
    except OSError:
        pass
    return owner_map


def resolve_owner(email: str, author: str, owner_map: dict[str, str]) -> str:
    """Map email or author to a team/owner label."""
    if email in owner_map:
        return owner_map[email]
    if author in owner_map:
        return owner_map[author]
    return author or email or "unknown"


def attach_owners(
    findings: list[Suppression],
    root: str,
    owner_map: dict[str, str] | None = None,
) -> list[Suppression]:
    """
    Attach owner metadata to findings and return the same list.
    """
    from dont_be_lazy.git import blame_lines, is_git_repo

    if not is_git_repo(root):
        for s in findings:
            s.owner = "unknown"
        return findings

    # Group by path to batch blame calls
    by_path: dict[str, list[tuple[int, Suppression]]] = collections.defaultdict(list)
    for s in findings:
        by_path[s.path].append((s.line, s))

    om = owner_map or {}

    for path, items in by_path.items():
        lines = [line for line, _ in items]
        blame_data = blame_lines(path, lines, root)
        for line, s in items:
            info = blame_data.get(line, {})
            s.git_author = info.get("author", "unknown")
            s.git_email = info.get("email", "")
            s.git_date = info.get("date", "")
            s.owner = resolve_owner(s.git_email or "", s.git_author or "", om)

    return findings


def format_owners_table(
    findings: list[Suppression],
    group_by: str = "author",
) -> str:
    groups: dict[str, list[Suppression]] = collections.defaultdict(list)
    for s in findings:
        if group_by == "email":
            key = s.git_email or "unknown"
        elif group_by == "team":
            key = s.owner or "unknown"
        elif group_by == "path":
            key = s.path
        else:
            key = s.git_author or "unknown"
        groups[key].append(s)

    lines = ["Suppressions by owner", ""]
    for owner in sorted(groups, key=lambda k: -len(groups[k])):
        rows = groups[owner]
        lines.append(f"\n{owner} ({len(rows)} suppressions)")
        lines.append("-" * 60)
        for s in rows:
            path_short = s.path[-40:] if len(s.path) > 40 else s.path
            text_short = s.text.strip()[:50]
            lines.append(f"  {s.risk.value:<8} {s.tool:<10} {path_short}:{s.line} — {text_short}")
    return "\n".join(lines) + "\n"


def format_owners_json(findings: list[Suppression]) -> str:
    from dont_be_lazy.formatters.json_fmt import _sup_to_dict

    items = []
    for s in findings:
        items.append(_sup_to_dict(s))
    return json.dumps({"findings": items}, indent=2)
