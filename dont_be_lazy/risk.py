"""Risk scoring for suppressions."""

from __future__ import annotations

from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression

_SECURITY_TOOLS = {"bandit", "semgrep", "secrets"}
_NO_CODE_TOOLS = {"black", "isort", "coverage"}  # these never carry codes; don't penalise

_BASE: dict[str, dict[str, RiskLevel]] = {
    "ruff": {
        "noqa-blanket": RiskLevel.high,
        "noqa-specific": RiskLevel.medium,
        "file-noqa": RiskLevel.high,
        "disable-block": RiskLevel.medium,
        "file-ignore": RiskLevel.high,
        "per-file-ignores": RiskLevel.medium,
        "config-ignore": RiskLevel.medium,
    },
    "flake8": {
        "noqa-blanket": RiskLevel.high,
        "noqa-specific": RiskLevel.medium,
        "file-noqa": RiskLevel.critical,
        "per-file-ignores": RiskLevel.medium,
        "malformed-noqa": RiskLevel.high,
    },
    "pylint": {
        "disable-all": RiskLevel.critical,
        "disable-module": RiskLevel.high,
        "disable-block": RiskLevel.high,
        "disable-line": RiskLevel.medium,
        "config-disable": RiskLevel.medium,
    },
    "mypy": {
        "type-ignore-blanket": RiskLevel.high,
        "type-ignore-specific": RiskLevel.medium,
        "file-ignore-errors": RiskLevel.critical,
        "ignore-missing-imports": RiskLevel.medium,
        "ignore-errors-config": RiskLevel.critical,
    },
    "pyright": {
        "ignore-blanket": RiskLevel.high,
        "ignore-specific": RiskLevel.medium,
        "type-checking-off": RiskLevel.critical,
        "diagnostic-none": RiskLevel.medium,
    },
    "bandit": {
        "nosec-blanket": RiskLevel.critical,
        "nosec-specific": RiskLevel.high,
        "config-skip": RiskLevel.high,
    },
    "coverage": {
        "no-cover": RiskLevel.medium,
        "no-branch": RiskLevel.low,
        "omit-broad": RiskLevel.critical,
        "exclude-lines-broad": RiskLevel.high,
    },
    "pytest": {
        "skip-unconditional": RiskLevel.high,
        "skip-with-reason": RiskLevel.medium,
        "skipif-with-reason": RiskLevel.low,
        "xfail-nonstrict": RiskLevel.medium,
        "xfail-strict": RiskLevel.low,
        "addopts-marker": RiskLevel.high,
    },
    "unittest": {
        "skip-unconditional": RiskLevel.high,
        "skip-conditional": RiskLevel.medium,
        "no-reason": RiskLevel.high,
    },
    "black": {
        "fmt-skip": RiskLevel.low,
        "fmt-off-block": RiskLevel.medium,
        "fmt-off-unclosed": RiskLevel.high,
    },
    "isort": {
        "skip-line": RiskLevel.low,
        "skip-file": RiskLevel.medium,
        "skip-glob-broad": RiskLevel.medium,
    },
}

_ORDER = [RiskLevel.low, RiskLevel.medium, RiskLevel.high, RiskLevel.critical]


def _bump(level: RiskLevel, steps: int = 1) -> RiskLevel:
    idx = min(len(_ORDER) - 1, _ORDER.index(level) + steps)
    return _ORDER[idx]


def discount(level: RiskLevel, steps: int = 1) -> RiskLevel:
    """Lower a risk level by the requested number of steps."""
    idx = max(0, _ORDER.index(level) - steps)
    return _ORDER[idx]


def score(s: Suppression) -> RiskLevel:
    """Derive a risk level for a suppression from its attributes."""
    tool_risks = _BASE.get(s.tool, {})
    base = tool_risks.get(s.kind, RiskLevel.medium)

    level = base

    if s.scope in (ScopeKind.file, ScopeKind.module):
        level = _bump(level)
    if s.scope == ScopeKind.config:
        level = _bump(level)
    if not s.codes and s.tool not in _NO_CODE_TOOLS:
        level = _bump(level)
    if not s.reason and s.tool not in _NO_CODE_TOOLS:
        level = _bump(level) if level < RiskLevel.high else level
    if s.tool in _SECURITY_TOOLS:
        level = _bump(level)
    if "unclosed-block-suppression" in s.flags:
        level = _bump(level)

    # Credits
    if s.codes:
        idx = max(0, _ORDER.index(level) - 1)
        level = _ORDER[idx]
    if s.reason and "expiry" in s.reason.lower():
        idx = max(0, _ORDER.index(level) - 1)
        level = _ORDER[idx]

    return level
