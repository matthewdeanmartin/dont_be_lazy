"""Token-level scanner for suppression comments in Python source files."""

from __future__ import annotations

import io
import re
import tokenize

from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------


NOQA_BLANKET = re.compile(r"#\s*noqa\s*$", re.IGNORECASE)
NOQA_SPECIFIC = re.compile(r"#\s*noqa\s*:\s*(?P<codes>[A-Z0-9,\s]+)", re.IGNORECASE)
RUFF_NOQA = re.compile(r"#\s*ruff\s*:\s*noqa(?:\s*:\s*(?P<codes>[A-Z0-9,\s]+))?", re.IGNORECASE)
FLAKE8_NOQA = re.compile(r"#\s*flake8\s*:\s*noqa", re.IGNORECASE)
RUFF_DISABLE = re.compile(r"#\s*ruff\s*:\s*disable\[(?P<codes>[^\]]+)\]", re.IGNORECASE)
RUFF_ENABLE = re.compile(r"#\s*ruff\s*:\s*enable\[(?P<codes>[^\]]+)\]", re.IGNORECASE)
RUFF_FILE_IGNORE = re.compile(r"#\s*ruff\s*:\s*file-ignore\[(?P<codes>[^\]]+)\]", re.IGNORECASE)

# inline mypy suppression comments
TYPE_IGNORE = re.compile(r"#\s*type\s*:\s*ignore(?:\[(?P<codes>[^\]]+)\])?")

# mypy file-level
MYPY_IGNORE_ERRORS = re.compile(r"#\s*mypy\s*:\s*ignore-errors", re.IGNORECASE)
MYPY_DISABLE_CODE = re.compile(r"#\s*mypy\s*:\s*disable-error-code\s*=\s*(?P<codes>[\w\-,\s]+)", re.IGNORECASE)

# pyright
PYRIGHT_IGNORE = re.compile(r"#\s*pyright\s*:\s*ignore(?:\[(?P<codes>[^\]]+)\])?", re.IGNORECASE)

# pylint
PYLINT_DISABLE = re.compile(
    r"#\s*pylint\s*:\s*(?P<verb>disable|enable|disable-next)\s*=\s*(?P<codes>[\w\-,\s]+)", re.IGNORECASE
)

# bandit
NOSEC = re.compile(r"#\s*nosec\s*(?P<codes>[B\d,\s]*)", re.IGNORECASE)

# fmt
FMT_SKIP = re.compile(r"#\s*fmt\s*:\s*skip", re.IGNORECASE)
FMT_OFF = re.compile(r"#\s*fmt\s*:\s*off", re.IGNORECASE)
FMT_ON = re.compile(r"#\s*fmt\s*:\s*on", re.IGNORECASE)

# isort
ISORT_SKIP = re.compile(r"#\s*isort\s*:\s*skip\b(?!_file)", re.IGNORECASE)
ISORT_SKIP_FILE = re.compile(r"#\s*isort\s*:\s*skip_file", re.IGNORECASE)
ISORT_OFF = re.compile(r"#\s*isort\s*:\s*off", re.IGNORECASE)
ISORT_ON = re.compile(r"#\s*isort\s*:\s*on", re.IGNORECASE)

# coverage
PRAGMA_NO_COVER = re.compile(r"#\s*pragma\s*:\s*no\s+cover", re.IGNORECASE)
PRAGMA_NO_BRANCH = re.compile(r"#\s*pragma\s*:\s*no\s+branch", re.IGNORECASE)

# pytype
PYTYPE_DISABLE = re.compile(r"#\s*pytype\s*:\s*disable\s*=\s*(?P<codes>[\w\-,\s]+)", re.IGNORECASE)
PYTYPE_ENABLE = re.compile(r"#\s*pytype\s*:\s*enable\s*=\s*(?P<codes>[\w\-,\s]+)", re.IGNORECASE)

# ty (Astral)
TY_IGNORE = re.compile(r"#\s*ty\s*:\s*ignore(?:\[(?P<codes>[^\]]+)\])?", re.IGNORECASE)

# semgrep
NOSEMGREP = re.compile(r"#\s*nosemgrep(?:\s*:\s*(?P<rule>[^\s#]+))?", re.IGNORECASE)

# detect-secrets
ALLOWLIST_SECRET = re.compile(r"#\s*pragma\s*:\s*allowlist\s+secret", re.IGNORECASE)
WHITELIST_SECRET = re.compile(r"#\s*pragma\s*:\s*whitelist\s+secret", re.IGNORECASE)

# autopep8
AUTOPEP8_OFF = re.compile(r"#\s*autopep8\s*:\s*off", re.IGNORECASE)
AUTOPEP8_ON = re.compile(r"#\s*autopep8\s*:\s*on", re.IGNORECASE)

# yapf
YAPF_DISABLE = re.compile(r"#\s*yapf\s*:\s*disable", re.IGNORECASE)
YAPF_ENABLE = re.compile(r"#\s*yapf\s*:\s*enable", re.IGNORECASE)

# NOSONAR (SonarQube)
NOSONAR = re.compile(r"#\s*NOSONAR\b")

# Suspicious free-text suppression phrases
SUSPICIOUS = re.compile(
    r"#.*\b("
    r"ignore\s+this|disable\s+check|suppress\s+warning|skip\s+lint"
    r"|TODO\s+fix\s+lint|temporary\s+ignore|hack\s*:\s*ignore"
    r"|lint\s*:\s*ignore|nocheck|NOLINT"
    r")\b",
    re.IGNORECASE,
)


def codes(raw: str | None) -> list[str]:
    """Parse a comma/space separated string of codes into a list."""
    if not raw:
        return []
    return [c.strip() for c in raw.replace(",", " ").split() if c.strip()]


def make(
    tool: str,
    kind: str,
    pattern: str,
    path: str,
    line: int,
    text: str,
    codes_list: list[str] | None = None,
    scope: ScopeKind = ScopeKind.line,
    end_line: int | None = None,
    flags: list[str] | None = None,
    risk: RiskLevel | None = None,
) -> Suppression:
    """Create a new Suppression object for a comment match."""
    return Suppression(
        tool=tool,
        kind=kind,
        pattern=pattern,
        path=path,
        line=line,
        end_line=end_line,
        scope=scope,
        codes=codes_list or [],
        reason=None,
        risk=risk or RiskLevel.medium,
        flags=flags or [],
        text=text,
    )


# ---------------------------------------------------------------------------
# Per-comment matching
# ---------------------------------------------------------------------------


def match_comment(
    comment: str,
    path: str,
    line: int,
    source_line: str,
    block_state: dict[str, list[Suppression]],
) -> list[Suppression]:
    """Match one comment token and return zero or more Suppression objects."""
    results: list[Suppression] = []

    # --- noqa blanket (must check before specific to avoid double-match) ---
    if NOQA_BLANKET.search(comment) and not NOQA_SPECIFIC.search(comment):
        results.append(
            make(
                "ruff", "noqa-blanket", "# noqa", path, line, source_line, risk=RiskLevel.high, flags=["blanket-ignore"]
            )
        )

    # --- noqa specific ---
    m = NOQA_SPECIFIC.search(comment)
    if m:
        c = codes(m.group("codes"))
        results.append(
            make(
                "ruff",
                "noqa-specific",
                f"# noqa: {m.group('codes')}",
                path,
                line,
                source_line,
                codes_list=c,
                risk=RiskLevel.medium,
            )
        )

    # --- ruff: noqa (file-wide) ---
    m = RUFF_NOQA.search(comment)
    if m:
        c = codes(m.group("codes"))
        kind = "file-noqa"
        results.append(
            make(
                "ruff",
                kind,
                comment.strip(),
                path,
                line,
                source_line,
                codes_list=c,
                scope=ScopeKind.file,
                risk=RiskLevel.high,
                flags=["file-wide"] if not c else [],
            )
        )

    # --- flake8: noqa (file-wide) ---
    if FLAKE8_NOQA.search(comment):
        results.append(
            make(
                "flake8",
                "file-noqa",
                "# flake8: noqa",
                path,
                line,
                source_line,
                scope=ScopeKind.file,
                risk=RiskLevel.critical,
                flags=["file-wide", "blanket-ignore"],
            )
        )

    # --- ruff: disable[...] block ---
    m = RUFF_DISABLE.search(comment)
    if m:
        c = codes(m.group("codes"))
        sup = make(
            "ruff",
            "disable-block",
            comment.strip(),
            path,
            line,
            source_line,
            codes_list=c,
            scope=ScopeKind.block,
            risk=RiskLevel.medium,
        )
        block_state.setdefault("ruff_disable", []).append(sup)
        results.append(sup)

    m = RUFF_ENABLE.search(comment)
    if m and "ruff_disable" in block_state and block_state["ruff_disable"]:
        open_sup = block_state["ruff_disable"].pop()
        open_sup.end_line = line

    # --- ruff: file-ignore[...] ---
    m = RUFF_FILE_IGNORE.search(comment)
    if m:
        c = codes(m.group("codes"))
        results.append(
            make(
                "ruff",
                "file-ignore",
                comment.strip(),
                path,
                line,
                source_line,
                codes_list=c,
                scope=ScopeKind.file,
                risk=RiskLevel.high,
            )
        )

    # --- type: ignore ---
    m = TYPE_IGNORE.search(comment)
    if m:
        c = codes(m.group("codes"))
        kind = "type-ignore-specific" if c else "type-ignore-blanket"
        risk = RiskLevel.medium if c else RiskLevel.high
        flags = [] if c else ["blanket-ignore"]
        results.append(
            make("mypy", kind, comment.strip(), path, line, source_line, codes_list=c, risk=risk, flags=flags)
        )

    # --- mypy: ignore-errors ---
    if MYPY_IGNORE_ERRORS.search(comment):
        results.append(
            make(
                "mypy",
                "file-ignore-errors",
                comment.strip(),
                path,
                line,
                source_line,
                scope=ScopeKind.file,
                risk=RiskLevel.critical,
                flags=["file-wide"],
            )
        )

    # --- mypy: disable-error-code ---
    m = MYPY_DISABLE_CODE.search(comment)
    if m:
        c = codes(m.group("codes"))
        results.append(
            make(
                "mypy",
                "disable-error-code",
                comment.strip(),
                path,
                line,
                source_line,
                codes_list=c,
                scope=ScopeKind.file,
                risk=RiskLevel.high,
            )
        )

    # --- pyright: ignore ---
    m = PYRIGHT_IGNORE.search(comment)
    if m:
        c = codes(m.group("codes"))
        kind = "ignore-specific" if c else "ignore-blanket"
        risk = RiskLevel.medium if c else RiskLevel.high
        flags = [] if c else ["blanket-ignore"]
        results.append(
            make("pyright", kind, comment.strip(), path, line, source_line, codes_list=c, risk=risk, flags=flags)
        )

    # --- pylint: disable/enable/disable-next ---
    m = PYLINT_DISABLE.search(comment)
    if m:
        verb = m.group("verb").lower()
        c = codes(m.group("codes"))
        if verb == "disable":
            if "all" in [code.lower() for code in c]:
                kind = "disable-all"
                risk = RiskLevel.critical
                flags = ["blanket-ignore"]
            else:
                kind = "disable-line"
                risk = RiskLevel.medium
                flags = []
            sup = make("pylint", kind, comment.strip(), path, line, source_line, codes_list=c, risk=risk, flags=flags)
            if verb == "disable" and kind != "disable-all":
                block_state.setdefault("pylint_disable", []).append(sup)
            results.append(sup)
        elif verb == "enable":
            if block_state.get("pylint_disable"):
                open_sup = block_state["pylint_disable"].pop()
                open_sup.end_line = line
                if open_sup.scope == ScopeKind.line:
                    open_sup.scope = ScopeKind.block
                    open_sup.kind = "disable-block"
                    open_sup.risk = RiskLevel.high
        elif verb == "disable-next":
            results.append(
                make(
                    "pylint",
                    "disable-next",
                    comment.strip(),
                    path,
                    line,
                    source_line,
                    codes_list=c,
                    scope=ScopeKind.next_line,
                    risk=RiskLevel.medium,
                )
            )

    # --- nosec ---
    m = NOSEC.search(comment)
    if m:
        c = codes(m.group("codes"))
        kind = "nosec-specific" if c else "nosec-blanket"
        risk = RiskLevel.high if c else RiskLevel.critical
        flags = [] if c else ["blanket-ignore"]
        results.append(
            make("bandit", kind, comment.strip(), path, line, source_line, codes_list=c, risk=risk, flags=flags)
        )

    # --- fmt: skip ---
    if FMT_SKIP.search(comment):
        results.append(make("black", "fmt-skip", "# fmt: skip", path, line, source_line, risk=RiskLevel.low))

    # --- fmt: off/on ---
    if FMT_OFF.search(comment):
        sup = make(
            "black",
            "fmt-off-block",
            "# fmt: off",
            path,
            line,
            source_line,
            scope=ScopeKind.block,
            risk=RiskLevel.medium,
        )
        block_state.setdefault("fmt_off", []).append(sup)
        results.append(sup)
    elif FMT_ON.search(comment):
        if block_state.get("fmt_off"):
            open_sup = block_state["fmt_off"].pop()
            open_sup.end_line = line

    # --- isort: skip_file ---
    if ISORT_SKIP_FILE.search(comment):
        results.append(
            make(
                "isort",
                "skip-file",
                "# isort: skip_file",
                path,
                line,
                source_line,
                scope=ScopeKind.file,
                risk=RiskLevel.medium,
            )
        )
    elif ISORT_SKIP.search(comment):
        results.append(make("isort", "skip-line", "# isort: skip", path, line, source_line, risk=RiskLevel.low))

    if ISORT_OFF.search(comment):
        sup = make(
            "isort",
            "isort-off-block",
            "# isort: off",
            path,
            line,
            source_line,
            scope=ScopeKind.block,
            risk=RiskLevel.medium,
        )
        block_state.setdefault("isort_off", []).append(sup)
        results.append(sup)
    elif ISORT_ON.search(comment):
        if block_state.get("isort_off"):
            open_sup = block_state["isort_off"].pop()
            open_sup.end_line = line

    # --- pragma: no cover ---
    if PRAGMA_NO_COVER.search(comment):
        results.append(
            make("coverage", "no-cover", "# pragma: no cover", path, line, source_line, risk=RiskLevel.medium)
        )

    # --- pragma: no branch ---
    if PRAGMA_NO_BRANCH.search(comment):
        results.append(
            make("coverage", "no-branch", "# pragma: no branch", path, line, source_line, risk=RiskLevel.low)
        )

    # --- pragma: allowlist/whitelist secret ---
    if ALLOWLIST_SECRET.search(comment) or WHITELIST_SECRET.search(comment):
        results.append(
            make(
                "secrets",
                "allowlist-secret",
                comment.strip(),
                path,
                line,
                source_line,
                risk=RiskLevel.high,
                flags=["security"],
            )
        )

    # --- pytype: disable/enable ---
    m = PYTYPE_DISABLE.search(comment)
    if m:
        c = codes(m.group("codes"))
        sup = make(
            "pytype",
            "disable-block",
            comment.strip(),
            path,
            line,
            source_line,
            codes_list=c,
            scope=ScopeKind.block,
            risk=RiskLevel.medium,
        )
        block_state.setdefault("pytype_disable", []).append(sup)
        results.append(sup)

    m = PYTYPE_ENABLE.search(comment)
    if m and "pytype_disable" in block_state and block_state["pytype_disable"]:
        open_sup = block_state["pytype_disable"].pop()
        open_sup.end_line = line

    # --- ty: ignore ---
    m = TY_IGNORE.search(comment)
    if m:
        c = codes(m.group("codes"))
        kind = "ignore-specific" if c else "ignore-blanket"
        risk = RiskLevel.medium if c else RiskLevel.high
        flags = [] if c else ["blanket-ignore"]
        results.append(make("ty", kind, comment.strip(), path, line, source_line, codes_list=c, risk=risk, flags=flags))

    # --- nosemgrep ---
    m = NOSEMGREP.search(comment)
    if m:
        rule = m.group("rule")
        kind = "nosemgrep-specific" if rule else "nosemgrep-blanket"
        c = [rule] if rule else []
        risk = RiskLevel.high if rule else RiskLevel.critical
        flags = [] if rule else ["blanket-ignore"]
        results.append(
            make("semgrep", kind, comment.strip(), path, line, source_line, codes_list=c, risk=risk, flags=flags)
        )

    # --- autopep8: off/on ---
    if AUTOPEP8_OFF.search(comment):
        sup = make(
            "autopep8",
            "autopep8-off-block",
            "# autopep8: off",
            path,
            line,
            source_line,
            scope=ScopeKind.block,
            risk=RiskLevel.medium,
        )
        block_state.setdefault("autopep8_off", []).append(sup)
        results.append(sup)
    elif AUTOPEP8_ON.search(comment):
        if block_state.get("autopep8_off"):
            open_sup = block_state["autopep8_off"].pop()
            open_sup.end_line = line

    # --- yapf: disable/enable ---
    if YAPF_DISABLE.search(comment):
        sup = make(
            "yapf",
            "yapf-disable-block",
            "# yapf: disable",
            path,
            line,
            source_line,
            scope=ScopeKind.block,
            risk=RiskLevel.medium,
        )
        block_state.setdefault("yapf_disable", []).append(sup)
        results.append(sup)
    elif YAPF_ENABLE.search(comment):
        if block_state.get("yapf_disable"):
            open_sup = block_state["yapf_disable"].pop()
            open_sup.end_line = line

    # --- NOSONAR ---
    if NOSONAR.search(comment):
        results.append(
            make(
                "sonar", "nosonar", "# NOSONAR", path, line, source_line, risk=RiskLevel.high, flags=["blanket-ignore"]
            )
        )

    # --- Suspicious free-text suppression phrases ---
    if SUSPICIOUS.search(comment) and not results:
        # Only add if no specific suppression already matched this comment
        results.append(
            make(
                "unknown",
                "suspicious-comment",
                comment.strip(),
                path,
                line,
                source_line,
                risk=RiskLevel.low,
                flags=["suspicious"],
            )
        )

    return results


def close_unclosed_blocks(block_state: dict[str, list[Suppression]]) -> None:
    """Mark all unclosed block suppressions with a flag and high risk."""
    for key in (
        "fmt_off",
        "isort_off",
        "ruff_disable",
        "pylint_disable",
        "pytype_disable",
        "autopep8_off",
        "yapf_disable",
    ):
        for sup in block_state.get(key, []):
            sup.flags.append("unclosed-block-suppression")
            # Don't downgrade risk; only upgrade if currently lower than high
            sup.risk = max(sup.risk, RiskLevel.high)


def scan_python_comments(path: str, source: str) -> list[Suppression]:
    """Scan a Python source file for suppression comments using tokenize."""
    results: list[Suppression] = []
    block_state: dict[str, list[Suppression]] = {}
    source_lines = source.splitlines()

    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenError:
        return results

    for tok_type, tok_string, tok_start, _, _ in tokens:
        if tok_type != tokenize.COMMENT:
            continue
        line_no = tok_start[0]
        source_line = source_lines[line_no - 1] if line_no <= len(source_lines) else ""
        found = match_comment(tok_string, path, line_no, source_line, block_state)
        results.extend(found)

    close_unclosed_blocks(block_state)
    return results
