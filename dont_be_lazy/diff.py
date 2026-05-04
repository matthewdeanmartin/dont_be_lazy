"""Git diff integration for --since REF scan mode."""

from __future__ import annotations

import os

from dont_be_lazy.git import changed_files_since, diff_hunks_since


def _native_repo_path(path: str) -> str:
    """Normalize a repo-relative path for local filesystem access."""
    return os.path.normpath(path.replace("\\", os.sep).replace("/", os.sep))


def _git_repo_path(path: str) -> str:
    """Normalize a repo-relative path for git pathspecs."""
    return path.replace("\\", "/")


def files_changed_since(ref: str, cwd: str) -> set[str]:
    """Return set of absolute paths changed since ref."""
    rel_paths = changed_files_since(ref, cwd)
    return {os.path.abspath(os.path.join(cwd, _native_repo_path(p))) for p in rel_paths}


def suppression_in_diff(
    suppression_line: int,
    hunks: list[tuple[int, int]],
) -> bool:
    """Return True if suppression_line falls within any changed hunk."""
    return any(start <= suppression_line <= end for start, end in hunks)


def build_diff_index(ref: str, paths: list[str], cwd: str) -> dict[str, list[tuple[int, int]]]:
    """Build {abs_path: [(start, end), ...]} for all changed files."""
    index: dict[str, list[tuple[int, int]]] = {}
    for p in paths:
        rel = _git_repo_path(os.path.relpath(p, cwd))
        hunks = diff_hunks_since(ref, rel, cwd)
        if hunks:
            index[p] = hunks
    return index
