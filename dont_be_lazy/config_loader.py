"""Config file discovery and loading for dont_be_lazy."""

from __future__ import annotations

import os
import sys
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[no-redef]
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            tomllib = None  # type: ignore[assignment]


def _load_toml(path: str) -> dict[str, Any]:
    if tomllib is None:
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def discover_config(root: str, explicit: str | None = None) -> dict[str, Any]:
    """Return the [tool.dont_be_lazy] config dict (or empty dict)."""
    if explicit:
        data = _load_toml(explicit)
        return data.get("tool", {}).get("dont_be_lazy", data)

    candidates = [
        os.path.join(root, "pyproject.toml"),
        os.path.join(root, "dont_be_lazy.toml"),
        os.path.join(root, ".dont-be-lazy.toml"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            data = _load_toml(path)
            section = data.get("tool", {}).get("dont_be_lazy", None)
            if section is not None:
                return section
            if "dont_be_lazy" in data or path.endswith("dont_be_lazy.toml") or path.endswith(".dont-be-lazy.toml"):
                return data

    return {}
