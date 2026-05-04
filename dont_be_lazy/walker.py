"""File walker for dont_be_lazy."""

from __future__ import annotations

import fnmatch
import os
import subprocess
from collections.abc import Iterator

DEFAULT_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
}

DEFAULT_EXTENSIONS = {".py", ".pyi", ".toml", ".ini", ".cfg", ".yaml", ".yml", ".json"}


def _gitignored_files(root: str) -> set | None:
    """Return set of repo-relative paths tracked by git, or None if not a git repo."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return {os.path.normpath(p) for p in result.stdout.splitlines() if p}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def walk_paths(
    root: str,
    include_globs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    respect_gitignore: bool = True,
    extensions: set | None = None,
) -> Iterator[str]:
    """Yield absolute file paths to scan under *root*."""
    if extensions is None:
        extensions = DEFAULT_EXTENSIONS

    git_files: set | None = None
    if respect_gitignore:
        git_files = _gitignored_files(root)

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_SKIP_DIRS and not d.startswith(".")]

        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if ext not in extensions:
                continue

            abs_path = os.path.join(dirpath, filename)
            rel_path = os.path.normpath(os.path.relpath(abs_path, root))

            if git_files is not None and rel_path not in git_files:
                continue

            if exclude_globs and any(fnmatch.fnmatch(rel_path, g) for g in exclude_globs):
                continue

            if include_globs and not any(fnmatch.fnmatch(rel_path, g) for g in include_globs):
                continue

            yield abs_path
