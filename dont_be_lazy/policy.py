"""Policy engine: applies DBL rule IDs to suppressions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dont_be_lazy.models import ScopeKind, Suppression


@dataclass
class PolicyViolation:
    rule_id: str
    message: str
    suppression: Suppression


_SECURITY_TOOLS = {"bandit", "semgrep", "secrets", "safety", "pip-audit"}
_TYPE_CHECKER_TOOLS = {"mypy", "pyright", "pytype", "ty"}
_TEST_TOOLS = {"pytest", "unittest", "hypothesis"}

_RULE_DESCRIPTIONS = {
    "DBL001": "Blanket inline suppression",
    "DBL002": "File-wide suppression",
    "DBL003": "Block suppression without matching enable",
    "DBL004": "Suppression has no reason",
    "DBL005": "Suppression is stale",
    "DBL006": "Security suppression",
    "DBL007": "Type checker suppression",
    "DBL008": "Skipped test",
    "DBL009": "Non-strict xfail",
    "DBL010": "Config-level rule ignore",
    "DBL011": "Config-level path exclusion",
    "DBL012": "Malformed suppression likely broader than intended",
    "DBL013": "Unknown/suspicious suppression comment",
    "DBL014": "Suppression in non-generated production code",
    "DBL015": "Vulnerability/dependency audit suppression",
}


def check(s: Suppression, policy: dict[str, Any] | None = None) -> list[PolicyViolation]:
    """Return all policy violations for a single suppression."""
    violations: list[PolicyViolation] = []
    p = policy or {}

    # DBL001 — blanket inline suppression
    if "blanket-ignore" in s.flags and s.scope == ScopeKind.line:
        violations.append(PolicyViolation("DBL001", _RULE_DESCRIPTIONS["DBL001"], s))

    # DBL002 — file-wide suppression
    if s.scope in (ScopeKind.file, ScopeKind.module) or "file-wide" in s.flags:
        violations.append(PolicyViolation("DBL002", _RULE_DESCRIPTIONS["DBL002"], s))

    # DBL003 — unclosed block
    if "unclosed-block-suppression" in s.flags:
        violations.append(PolicyViolation("DBL003", _RULE_DESCRIPTIONS["DBL003"], s))

    # DBL004 — no reason
    require_reason = p.get("require_reason", False)
    tool_policy = p.get("by_tool", {}).get(s.tool, {})
    if tool_policy.get("require_reason", require_reason) and not s.reason:
        violations.append(PolicyViolation("DBL004", _RULE_DESCRIPTIONS["DBL004"], s))

    # DBL006 — security suppression
    if s.tool in _SECURITY_TOOLS:
        violations.append(PolicyViolation("DBL006", _RULE_DESCRIPTIONS["DBL006"], s))

    # DBL007 — type checker suppression
    if s.tool in _TYPE_CHECKER_TOOLS:
        violations.append(PolicyViolation("DBL007", _RULE_DESCRIPTIONS["DBL007"], s))

    # DBL008 — skipped test
    if s.scope == ScopeKind.test and s.tool in _TEST_TOOLS:
        violations.append(PolicyViolation("DBL008", _RULE_DESCRIPTIONS["DBL008"], s))

    # DBL009 — non-strict xfail
    if s.kind == "xfail-nonstrict":
        violations.append(PolicyViolation("DBL009", _RULE_DESCRIPTIONS["DBL009"], s))

    # DBL010 — config-level rule ignore
    if s.scope == ScopeKind.config and "ignore" in s.kind:
        violations.append(PolicyViolation("DBL010", _RULE_DESCRIPTIONS["DBL010"], s))

    # DBL011 — config-level path exclusion
    if s.scope == ScopeKind.config and "exclude" in s.kind:
        violations.append(PolicyViolation("DBL011", _RULE_DESCRIPTIONS["DBL011"], s))

    # DBL012 — malformed suppression (flagged by scanner)
    if "malformed" in s.flags or "malformed" in s.kind:
        violations.append(PolicyViolation("DBL012", _RULE_DESCRIPTIONS["DBL012"], s))

    # DBL013 — unknown/suspicious
    if s.tool == "unknown" or "suspicious" in s.flags:
        violations.append(PolicyViolation("DBL013", _RULE_DESCRIPTIONS["DBL013"], s))

    # DBL015 — vulnerability / dep audit suppression
    if s.tool in ("safety", "pip-audit") and "ignored-vulnerability" in s.kind:
        violations.append(PolicyViolation("DBL015", _RULE_DESCRIPTIONS["DBL015"], s))

    return violations


def check_all(
    findings: list[Suppression],
    policy: dict[str, Any] | None = None,
) -> list[PolicyViolation]:
    """Run policy checks against all findings."""
    violations: list[PolicyViolation] = []
    for s in findings:
        violations.extend(check(s, policy))
    return violations


def rules_table() -> list[dict[str, str]]:
    """Return all rule IDs and descriptions."""
    return [{"id": k, "description": v} for k, v in _RULE_DESCRIPTIONS.items()]
