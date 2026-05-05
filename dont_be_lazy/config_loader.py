"""Config file discovery and loading for dont_be_lazy."""

from __future__ import annotations

import importlib
import os
from typing import Any, cast

from dont_be_lazy.git import GIT_BIN, run


def load_optional_module(*names: str) -> Any | None:
    """Import the first available module from *names*."""
    for name in names:
        try:
            return importlib.import_module(name)
        except ModuleNotFoundError:
            continue
    return None


tomllib = load_optional_module("tomllib", "tomli")


def find_root(explicit: str | None = None) -> str:
    """Return the repository root or current directory."""
    if explicit:
        return os.path.abspath(explicit)
    root = run([GIT_BIN, "rev-parse", "--show-toplevel"], cwd=os.getcwd())
    if root is not None:
        return root.strip()
    return os.getcwd()


def load_toml(path: str) -> dict[str, Any]:
    """Load a TOML file into a dictionary."""
    if tomllib is None:
        return {}
    with open(path, "rb") as f:
        return cast(dict[str, Any], tomllib.load(f))


def discover_config(root: str, explicit: str | None = None) -> dict[str, Any]:
    """Return the [tool.dont_be_lazy] config dict (or empty dict)."""
    if explicit:
        data = load_toml(explicit)
        tool_section = data.get("tool", {})
        if isinstance(tool_section, dict):
            dont_be_lazy_section = tool_section.get("dont_be_lazy")
            if isinstance(dont_be_lazy_section, dict):
                return dont_be_lazy_section
        return data

    candidates = [
        os.path.join(root, "pyproject.toml"),
        os.path.join(root, "dont_be_lazy.toml"),
        os.path.join(root, ".dont-be-lazy.toml"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            data = load_toml(path)
            tool_section = data.get("tool", {})
            section = tool_section.get("dont_be_lazy") if isinstance(tool_section, dict) else None
            if isinstance(section, dict):
                return section
            if "dont_be_lazy" in data or path.endswith("dont_be_lazy.toml") or path.endswith(".dont-be-lazy.toml"):
                return data

    return {}
