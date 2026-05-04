"""explain subcommand: detailed explanation of a single suppression."""

from __future__ import annotations

import os
from typing import Any

from dont_be_lazy.models import ScopeKind, Suppression

# Per-tool review prompts
_REVIEW_PROMPTS: dict = {
    "ruff": [
        "Can the code be changed to satisfy the rule?",
        "Is the rule still enabled in the current config?",
        "Is the ignore too broad? Can it be limited to a specific code?",
        "Is this generated code that should be excluded at the config level?",
    ],
    "flake8": [
        "Can the code be changed to satisfy the rule?",
        "Is the rule still enabled in the current config?",
        "Can the ignore be limited to a specific error code?",
    ],
    "pylint": [
        "Can the code be refactored to pass the pylint check?",
        "Is this disable still needed or was the issue fixed?",
        "Is the disable too broad? Consider narrowing to one message.",
    ],
    "mypy": [
        "Is the library now typed or does it have stubs available?",
        "Would `cast`, `Protocol`, `TypedDict`, or a stub fix this?",
        "Is the ignored code hiding more than one error?",
        "Can the ignore be code-specific (`type: ignore[code]`)?",
    ],
    "pyright": [
        "Is the library now typed or does it have stubs available?",
        "Can the ignore be code-specific (`pyright: ignore[rule]`)?",
        "Is `typeCheckingMode` set to `off` for the whole project?",
    ],
    "pytype": [
        "Can the code be annotated to satisfy pytype?",
        "Can the disable be narrowed to a specific error class?",
        "Is the block disable ever closed with a matching enable?",
    ],
    "ty": [
        "Is the library now typed?",
        "Can the ignore be code-specific (`ty: ignore[rule]`)?",
    ],
    "bandit": [
        "Is the suppressed issue security-relevant in this context?",
        "Is there a threat model note or security review linked?",
        "Is there an issue link or expiry date?",
        "Can the code be made safe instead of suppressing the warning?",
    ],
    "semgrep": [
        "Is there a threat model note explaining why the rule doesn't apply?",
        "Can the code be changed to avoid the pattern?",
        "Is there a ticket for follow-up?",
    ],
    "secrets": [
        "Is this a real secret or a test fixture value?",
        "Should this be moved to environment variables or a secrets manager?",
    ],
    "pytest": [
        "Is the skip/xfail still needed?",
        "Is it unconditional when it should be conditional?",
        "Does it have a reason?",
        "Does `xfail` use `strict=True`?",
        "Is there a ticket for removal?",
    ],
    "unittest": [
        "Is the skip still needed?",
        "Is there a reason provided?",
        "Is the condition still accurate?",
    ],
    "hypothesis": [
        "Is the suppressed health check still relevant?",
        "Can the test be refactored to avoid the health check failure?",
        "Is `deadline=None` masking slow tests?",
    ],
    "coverage": [
        "Is the excluded code truly unreachable or platform-specific?",
        "Is the exclusion hiding untested production logic?",
        "Is a whole file or path omitted when only specific lines should be?",
    ],
    "black": [
        "Is the formatted code unreadable enough to justify disabling?",
        "Is the `fmt: off` block ever closed with `fmt: on`?",
    ],
    "isort": [
        "Is the import ordering important enough to bypass isort here?",
        "Would a comment explaining the ordering intent be useful?",
    ],
}

_DEFAULT_PROMPTS = [
    "Is this suppression still necessary?",
    "Is there a reason or issue link?",
    "Can the underlying issue be fixed instead of suppressed?",
]


def _why_suppression(s: Suppression) -> str:
    kind_descriptions = {
        "noqa-blanket": "suppresses all linting rules on this line without specifying which.",
        "noqa-specific": "suppresses specific linting error code(s) on this line.",
        "noqa-file": "suppresses all linting checks for the entire file.",
        "type-ignore-blanket": "suppresses all type checker errors on this line.",
        "type-ignore-specific": "suppresses specific type checker error code(s) on this line.",
        "mypy-file-ignore": "tells mypy to ignore all errors in this file.",
        "pylint-disable": "disables one or more pylint messages.",
        "pylint-disable-all": "disables ALL pylint messages — extremely broad suppression.",
        "nosec": "suppresses all Bandit security checks on this line.",
        "nosec-specific": "suppresses specific Bandit check ID(s) on this line.",
        "nosemgrep": "suppresses all Semgrep rules on this line.",
        "nosemgrep-specific": "suppresses specific Semgrep rule(s) on this line.",
        "skip-unconditional": "unconditionally skips this test — it will never run.",
        "skip-conditional": "conditionally skips this test.",
        "xfail-nonstrict": "marks the test as expected to fail; if it passes, it's silently ignored.",
        "xfail-strict": "marks the test as expected to fail; if it passes, it becomes an error.",
        "pragma-no-cover": "excludes this code from coverage measurement.",
        "pragma-no-branch": "excludes a branch from coverage measurement.",
        "fmt-skip": "prevents the formatter from reformatting this line.",
        "fmt-off": "disables the formatter for a block of code.",
        "isort-skip": "prevents isort from reordering this import.",
        "config-ignore": "ignores specific error/rule codes across the project via config.",
        "config-exclude": "excludes a file or directory from tool analysis via config.",
        "config-skip": "skips processing for specific paths via config.",
    }
    desc = kind_descriptions.get(s.kind, f"is a `{s.kind}` suppression.")
    return f"This {desc}"


def _scope_explanation(s: Suppression) -> str:
    scope_text = {
        ScopeKind.line: "Affects only this line.",
        ScopeKind.next_line: "Affects the next line only.",
        ScopeKind.block: f"Affects a block from line {s.line} to {s.end_line or '?'}.",
        ScopeKind.file: "Affects the entire file.",
        ScopeKind.module: "Affects the entire module.",
        ScopeKind.config: "Affects the entire project via configuration.",
        ScopeKind.path: "Affects all files matching the specified path/glob.",
        ScopeKind.test: "Affects a test function or class.",
        ScopeKind.unknown: "Scope is unknown.",
    }
    return scope_text.get(s.scope, f"Scope: {s.scope.value}")


def _risk_rationale(s: Suppression) -> str:
    parts = []
    if "blanket-suppression" in s.flags or not s.codes:
        parts.append("No specific code — blanket suppression.")
    if "no-reason" in s.flags or not s.reason:
        parts.append("No reason provided.")
    if "unclosed-block-suppression" in s.flags:
        parts.append("Block suppression is never closed.")
    if s.scope in (ScopeKind.file, ScopeKind.module, ScopeKind.config):
        parts.append("File/module/config-wide scope increases risk.")
    if s.tool in ("bandit", "semgrep", "secrets"):
        parts.append("Suppresses a security tool.")
    if not parts:
        parts.append("Risk is based on tool, kind, and scope combination.")
    return " ".join(parts)


def explain_suppression(s: Suppression) -> str:
    prompts = _REVIEW_PROMPTS.get(s.tool, _DEFAULT_PROMPTS)

    lines = [
        f"{s.path}:{s.line}",
        "",
        f"Matched: {s.tool} — {s.kind}",
        f"Pattern: {s.text.strip()}",
        f"Scope:   {s.scope.value}",
        f"Risk:    {s.risk.value.upper()}",
    ]

    if s.codes:
        lines.append(f"Codes:   {', '.join(s.codes)}")
    if s.reason:
        lines.append(f"Reason:  {s.reason}")
    if s.flags:
        lines.append(f"Flags:   {', '.join(s.flags)}")

    lines.extend(
        [
            "",
            "Why:",
            f"  {_why_suppression(s)}",
            f"  {_scope_explanation(s)}",
            "",
            "Risk rationale:",
            f"  {_risk_rationale(s)}",
            "",
            "Review:",
        ]
    )
    for prompt in prompts:
        lines.append(f"  - {prompt}")

    return "\n".join(lines) + "\n"


def explain_suppression_json(s: Suppression) -> dict[str, Any]:
    """Return structured explain output."""
    return {
        "finding": {
            "id": s.id,
            "path": s.path,
            "line": s.line,
            "tool": s.tool,
            "kind": s.kind,
            "scope": s.scope.value,
            "risk": s.risk.value,
            "codes": s.codes,
            "reason": s.reason,
            "flags": s.flags,
            "text": s.text,
        },
        "why": _why_suppression(s),
        "risk_rationale": _risk_rationale(s),
        "review": _REVIEW_PROMPTS.get(s.tool, _DEFAULT_PROMPTS),
        "blanket": not bool(s.codes) or "blanket-ignore" in s.flags,
        "code_specific": bool(s.codes),
    }


def find_suppression_by_id(findings: list[Suppression], dbl_id: str) -> Suppression | None:
    dbl_id = dbl_id.upper()
    for s in findings:
        if s.id == dbl_id:
            return s
    return None


def find_suppression_by_location(findings: list[Suppression], path: str, line: int) -> Suppression | None:
    normalized_target = os.path.normpath(path)
    for s in findings:
        if s.line != line:
            continue
        normalized_path = os.path.normpath(s.path)
        if normalized_path == normalized_target or normalized_path.endswith(normalized_target):
            return s
    return None
