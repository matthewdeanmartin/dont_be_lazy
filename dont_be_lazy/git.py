"""Git integration: blame, log -S, diff for Phase 3 features."""

from __future__ import annotations

import re
import subprocess
from datetime import datetime


def _run(args: list[str], cwd: str, timeout: int = 15) -> str | None:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return None


def is_git_repo(path: str) -> bool:
    return _run(["git", "rev-parse", "--git-dir"], cwd=path) is not None


def blame_line(path: str, line: int, cwd: str) -> dict[str, str] | None:
    """Return {'author': ..., 'email': ..., 'date': 'YYYY-MM-DD'} for a line, or None."""
    out = _run(
        ["git", "blame", "-L", f"{line},{line}", "--porcelain", path],
        cwd=cwd,
    )
    if not out:
        return None
    info: dict[str, str] = {}
    for ln in out.splitlines():
        if ln.startswith("author "):
            info["author"] = ln[len("author ") :].strip()
        elif ln.startswith("author-mail "):
            info["email"] = ln[len("author-mail ") :].strip().strip("<>")
        elif ln.startswith("author-time "):
            ts = ln[len("author-time ") :].strip()
            try:
                info["date"] = datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d")
            except ValueError:
                pass
    return info if info else None


def blame_lines(path: str, lines: list[int], cwd: str) -> dict[int, dict[str, str]]:
    """Blame multiple lines in one call. Returns {line_number: info}."""
    if not lines:
        return {}
    lo, hi = min(lines), max(lines)
    out = _run(
        ["git", "blame", "-L", f"{lo},{hi}", "--porcelain", path],
        cwd=cwd,
    )
    if not out:
        return {}

    result: dict[int, dict[str, str]] = {}
    current_line = lo - 1
    current_info: dict[str, str] = {}

    for ln in out.splitlines():
        # Header line: <sha> <orig-line> <result-line> [<num-lines>]
        header_m = re.match(r"^[0-9a-f]{40} \d+ (\d+)", ln)
        if header_m:
            if current_line in lines and current_info:
                result[current_line] = dict(current_info)
            current_line = int(header_m.group(1))
            current_info = {}
        elif ln.startswith("author "):
            current_info["author"] = ln[7:].strip()
        elif ln.startswith("author-mail "):
            current_info["email"] = ln[12:].strip().strip("<>")
        elif ln.startswith("author-time "):
            ts = ln[12:].strip()
            try:
                current_info["date"] = datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d")
            except ValueError:
                pass

    if current_line in lines and current_info:
        result[current_line] = dict(current_info)

    return result


def first_seen_by_log(path: str, text: str, cwd: str) -> str | None:
    """Estimate first commit that introduced `text` in `path` using git log -S.

    Returns 'YYYY-MM-DD' or None.
    """
    # Use -S to find commits that added/removed the text
    out = _run(
        ["git", "log", "--diff-filter=A", "--follow", "--format=%ai", "-S", text, "--", path],
        cwd=cwd,
        timeout=30,
    )
    if not out:
        # Fall back: any commit touching that text
        out = _run(
            ["git", "log", "--format=%ai", "-S", text, "--", path],
            cwd=cwd,
            timeout=30,
        )
    if not out:
        return None
    # Pick the earliest date (last line = oldest commit in chronological log)
    dates = []
    for line in out.strip().splitlines():
        m = re.match(r"(\d{4}-\d{2}-\d{2})", line.strip())
        if m:
            dates.append(m.group(1))
    if not dates:
        return None
    return min(dates)  # earliest


def changed_files_since(ref: str, cwd: str) -> list[str]:
    """Return list of file paths changed since `ref` (git diff --name-only REF)."""
    out = _run(["git", "diff", "--name-only", ref], cwd=cwd)
    if not out:
        return []
    return [p.strip() for p in out.splitlines() if p.strip()]


def diff_hunks_since(ref: str, path: str, cwd: str) -> list[tuple[int, int]]:
    """Return list of (start_line, end_line) hunks changed in path since ref."""
    out = _run(["git", "diff", "-U0", ref, "--", path], cwd=cwd)
    if not out:
        return []
    hunks: list[tuple[int, int]] = []
    for ln in out.splitlines():
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", ln)
        if m:
            start = int(m.group(1))
            length = int(m.group(2)) if m.group(2) is not None else 1
            if length > 0:
                hunks.append((start, start + length - 1))
    return hunks
