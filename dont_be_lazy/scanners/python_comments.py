"""Token-level scanner for suppression comments in Python source files."""

from __future__ import annotations

import io
import re
import tokenize

from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------


_NOQA_BLANKET = re.compile(r"#\s*noqa\s*$", re.IGNORECASE)
_NOQA_SPECIFIC = re.compile(r"#\s*noqa\s*:\s*(?P<codes>[A-Z0-9,\s]+)", re.IGNORECASE)
_RUFF_NOQA = re.compile(r"#\s*ruff\s*:\s*noqa(?:\s*:\s*(?P<codes>[A-Z0-9,\s]+))?", re.IGNORECASE)
_FLAKE8_NOQA = re.compile(r"#\s*flake8\s*:\s*noqa", re.IGNORECASE)
_RUFF_DISABLE = re.compile(r"#\s*ruff\s*:\s*disable\[(?P<codes>[^\]]+)\]", re.IGNORECASE)
_RUFF_ENABLE = re.compile(r"#\s*ruff\s*:\s*enable\[(?P<codes>[^\]]+)\]", re.IGNORECASE)
_RUFF_FILE_IGNORE = re.compile(r"#\s*ruff\s*:\s*file-ignore\[(?P<codes>[^\]]+)\]", re.IGNORECASE)

# inline mypy suppression comments
_TYPE_IGNORE = re.compile(r"#\s*type\s*:\s*ignore(?:\[(?P<codes>[^\]]+)\])?")

# mypy file-level
_MYPY_IGNORE_ERRORS = re.compile(r"#\s*mypy\s*:\s*ignore-errors", re.IGNORECASE)
_MYPY_DISABLE_CODE = re.compile(r"#\s*mypy\s*:\s*disable-error-code\s*=\s*(?P<codes>[\w\-,\s]+)", re.IGNORECASE)

# pyright
_PYRIGHT_IGNORE = re.compile(r"#\s*pyright\s*:\s*ignore(?:\[(?P<codes>[^\]]+)\])?", re.IGNORECASE)

# pylint
_PYLINT_DISABLE = re.compile(
    r"#\s*pylint\s*:\s*(?P<verb>disable|enable|disable-next)\s*=\s*(?P<codes>[\w\-,\s]+)", re.IGNORECASE
)

# bandit
_NOSEC = re.compile(r"#\s*nosec\s*(?P<codes>[B\d,\s]*)", re.IGNORECASE)

# fmt
_FMT_SKIP = re.compile(r"#\s*fmt\s*:\s*skip", re.IGNORECASE)
_FMT_OFF = re.compile(r"#\s*fmt\s*:\s*off", re.IGNORECASE)
_FMT_ON = re.compile(r"#\s*fmt\s*:\s*on", re.IGNORECASE)

# isort
_ISORT_SKIP = re.compile(r"#\s*isort\s*:\s*skip\b(?!_file)", re.IGNORECASE)
_ISORT_SKIP_FILE = re.compile(r"#\s*isort\s*:\s*skip_file", re.IGNORECASE)
_ISORT_OFF = re.compile(r"#\s*isort\s*:\s*off", re.IGNORECASE)
_ISORT_ON = re.compile(r"#\s*isort\s*:\s*on", re.IGNORECASE)

# coverage
_PRAGMA_NO_COVER = re.compile(r"#\s*pragma\s*:\s*no\s+cover", re.IGNORECASE)
_PRAGMA_NO_BRANCH = re.compile(r"#\s*pragma\s*:\s*no\s+branch", re.IGNORECASE)

# pytype
_PYTYPE_DISABLE = re.compile(r"#\s*pytype\s*:\s*disable\s*=\s*(?P<codes>[\w\-,\s]+)", re.IGNORECASE)
_PYTYPE_ENABLE = re.compile(r"#\s*pytype\s*:\s*enable\s*=\s*(?P<codes>[\w\-,\s]+)", re.IGNORECASE)

# ty (Astral)
_TY_IGNORE = re.compile(r"#\s*ty\s*:\s*ignore(?:\[(?P<codes>[^\]]+)\])?", re.IGNORECASE)

# semgrep
_NOSEMGREP = re.compile(r"#\s*nosemgrep(?:\s*:\s*(?P<rule>[^\s#]+))?", re.IGNORECASE)

# detect-secrets
_ALLOWLIST_SECRET = re.compile(r"#\s*pragma\s*:\s*allowlist\s+secret", re.IGNORECASE)
_WHITELIST_SECRET = re.compile(r"#\s*pragma\s*:\s*whitelist\s+secret", re.IGNORECASE)

# autopep8
_AUTOPEP8_OFF = re.compile(r"#\s*autopep8\s*:\s*off", re.IGNORECASE)
_AUTOPEP8_ON = re.compile(r"#\s*autopep8\s*:\s*on", re.IGNORECASE)

# yapf
_YAPF_DISABLE = re.compile(r"#\s*yapf\s*:\s*disable", re.IGNORECASE)
_YAPF_ENABLE = re.compile(r"#\s*yapf\s*:\s*enable", re.IGNORECASE)

# NOSONAR (SonarQube)
_NOSONAR = re.compile(r"#\s*NOSONAR\b")

# Suspicious free-text suppression phrases
_SUSPICIOUS = re.compile(
    r"#.*\b("
    r"ignore\s+this|disable\s+check|suppress\s+warning|skip\s+lint"
    r"|TODO\s+fix\s+lint|temporary\s+ignore|hack\s*:\s*ignore"
    r"|lint\s*:\s*ignore|nocheck|NOLINT"
    r")\b",
    re.IGNORECASE,
)


def _codes(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [c.strip() for c in raw.replace(",", " ").split() if c.strip()]


def _make(
    tool: str,
    kind: str,
    pattern: str,
    path: str,
    line: int,
    text: str,
    codes: list[str] | None = None,
    scope: ScopeKind = ScopeKind.line,
    end_line: int | None = None,
    flags: list[str] | None = None,
    risk: RiskLevel | None = None,
) -> Suppression:
    return Suppression(
        tool=tool,
        kind=kind,
        pattern=pattern,
        path=path,
        line=line,
        end_line=end_line,
        scope=scope,
        codes=codes or [],
        reason=None,
        risk=risk or RiskLevel.medium,
        flags=flags or [],
        text=text,
    )


# ---------------------------------------------------------------------------
# Per-comment matching
# ---------------------------------------------------------------------------


def _match_comment(
    comment: str,
    path: str,
    line: int,
    source_line: str,
    block_state: dict[str, list[Suppression]],
) -> list[Suppression]:
    """Match one comment token and return zero or more Suppression objects."""
    results: list[Suppression] = []

    # --- noqa blanket (must check before specific to avoid double-match) ---
    if _NOQA_BLANKET.search(comment) and not _NOQA_SPECIFIC.search(comment):
        results.append(
            _make(
                "ruff", "noqa-blanket", "# noqa", path, line, source_line, risk=RiskLevel.high, flags=["blanket-ignore"]
            )
        )

    # --- noqa specific ---
    m = _NOQA_SPECIFIC.search(comment)
    if m:
        codes = _codes(m.group("codes"))
        results.append(
            _make(
                "ruff",
                "noqa-specific",
                f"# noqa: {m.group('codes')}",
                path,
                line,
                source_line,
                codes=codes,
                risk=RiskLevel.medium,
            )
        )

    # --- ruff: noqa (file-wide) ---
    m = _RUFF_NOQA.search(comment)
    if m:
        codes = _codes(m.group("codes"))
        kind = "file-noqa"
        results.append(
            _make(
                "ruff",
                kind,
                comment.strip(),
                path,
                line,
                source_line,
                codes=codes,
                scope=ScopeKind.file,
                risk=RiskLevel.high,
                flags=["file-wide"] if not codes else [],
            )
        )

    # --- flake8: noqa (file-wide) ---
    if _FLAKE8_NOQA.search(comment):
        results.append(
            _make(
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
    m = _RUFF_DISABLE.search(comment)
    if m:
        codes = _codes(m.group("codes"))
        sup = _make(
            "ruff",
            "disable-block",
            comment.strip(),
            path,
            line,
            source_line,
            codes=codes,
            scope=ScopeKind.block,
            risk=RiskLevel.medium,
        )
        block_state.setdefault("ruff_disable", []).append(sup)
        results.append(sup)

    m = _RUFF_ENABLE.search(comment)
    if m and "ruff_disable" in block_state and block_state["ruff_disable"]:
        open_sup = block_state["ruff_disable"].pop()
        open_sup.end_line = line

    # --- ruff: file-ignore[...] ---
    m = _RUFF_FILE_IGNORE.search(comment)
    if m:
        codes = _codes(m.group("codes"))
        results.append(
            _make(
                "ruff",
                "file-ignore",
                comment.strip(),
                path,
                line,
                source_line,
                codes=codes,
                scope=ScopeKind.file,
                risk=RiskLevel.high,
            )
        )

    # --- type: ignore ---
    m = _TYPE_IGNORE.search(comment)
    if m:
        codes = _codes(m.group("codes"))
        kind = "type-ignore-specific" if codes else "type-ignore-blanket"
        risk = RiskLevel.medium if codes else RiskLevel.high
        flags = [] if codes else ["blanket-ignore"]
        results.append(
            _make("mypy", kind, comment.strip(), path, line, source_line, codes=codes, risk=risk, flags=flags)
        )

    # --- mypy: ignore-errors ---
    if _MYPY_IGNORE_ERRORS.search(comment):
        results.append(
            _make(
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
    m = _MYPY_DISABLE_CODE.search(comment)
    if m:
        codes = _codes(m.group("codes"))
        results.append(
            _make(
                "mypy",
                "disable-error-code",
                comment.strip(),
                path,
                line,
                source_line,
                codes=codes,
                scope=ScopeKind.file,
                risk=RiskLevel.high,
            )
        )

    # --- pyright: ignore ---
    m = _PYRIGHT_IGNORE.search(comment)
    if m:
        codes = _codes(m.group("codes"))
        kind = "ignore-specific" if codes else "ignore-blanket"
        risk = RiskLevel.medium if codes else RiskLevel.high
        flags = [] if codes else ["blanket-ignore"]
        results.append(
            _make("pyright", kind, comment.strip(), path, line, source_line, codes=codes, risk=risk, flags=flags)
        )

    # --- pylint: disable/enable/disable-next ---
    m = _PYLINT_DISABLE.search(comment)
    if m:
        verb = m.group("verb").lower()
        codes = _codes(m.group("codes"))
        if verb == "disable":
            if "all" in [c.lower() for c in codes]:
                kind = "disable-all"
                risk = RiskLevel.critical
                flags = ["blanket-ignore"]
            else:
                kind = "disable-line"
                risk = RiskLevel.medium
                flags = []
            sup = _make("pylint", kind, comment.strip(), path, line, source_line, codes=codes, risk=risk, flags=flags)
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
                _make(
                    "pylint",
                    "disable-next",
                    comment.strip(),
                    path,
                    line,
                    source_line,
                    codes=codes,
                    scope=ScopeKind.next_line,
                    risk=RiskLevel.medium,
                )
            )

    # --- nosec ---
    m = _NOSEC.search(comment)
    if m:
        codes = _codes(m.group("codes"))
        kind = "nosec-specific" if codes else "nosec-blanket"
        risk = RiskLevel.high if codes else RiskLevel.critical
        flags = [] if codes else ["blanket-ignore"]
        results.append(
            _make("bandit", kind, comment.strip(), path, line, source_line, codes=codes, risk=risk, flags=flags)
        )

    # --- fmt: skip ---
    if _FMT_SKIP.search(comment):
        results.append(_make("black", "fmt-skip", "# fmt: skip", path, line, source_line, risk=RiskLevel.low))

    # --- fmt: off/on ---
    if _FMT_OFF.search(comment):
        sup = _make(
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
    elif _FMT_ON.search(comment):
        if block_state.get("fmt_off"):
            open_sup = block_state["fmt_off"].pop()
            open_sup.end_line = line

    # --- isort: skip_file ---
    if _ISORT_SKIP_FILE.search(comment):
        results.append(
            _make(
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
    elif _ISORT_SKIP.search(comment):
        results.append(_make("isort", "skip-line", "# isort: skip", path, line, source_line, risk=RiskLevel.low))

    if _ISORT_OFF.search(comment):
        sup = _make(
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
    elif _ISORT_ON.search(comment):
        if block_state.get("isort_off"):
            open_sup = block_state["isort_off"].pop()
            open_sup.end_line = line

    # --- pragma: no cover ---
    if _PRAGMA_NO_COVER.search(comment):
        results.append(
            _make("coverage", "no-cover", "# pragma: no cover", path, line, source_line, risk=RiskLevel.medium)
        )

    # --- pragma: no branch ---
    if _PRAGMA_NO_BRANCH.search(comment):
        results.append(
            _make("coverage", "no-branch", "# pragma: no branch", path, line, source_line, risk=RiskLevel.low)
        )

    # --- pragma: allowlist/whitelist secret ---
    if _ALLOWLIST_SECRET.search(comment) or _WHITELIST_SECRET.search(comment):
        results.append(
            _make(
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
    m = _PYTYPE_DISABLE.search(comment)
    if m:
        codes = _codes(m.group("codes"))
        sup = _make(
            "pytype",
            "disable-block",
            comment.strip(),
            path,
            line,
            source_line,
            codes=codes,
            scope=ScopeKind.block,
            risk=RiskLevel.medium,
        )
        block_state.setdefault("pytype_disable", []).append(sup)
        results.append(sup)

    m = _PYTYPE_ENABLE.search(comment)
    if m and "pytype_disable" in block_state and block_state["pytype_disable"]:
        open_sup = block_state["pytype_disable"].pop()
        open_sup.end_line = line

    # --- ty: ignore ---
    m = _TY_IGNORE.search(comment)
    if m:
        codes = _codes(m.group("codes"))
        kind = "ignore-specific" if codes else "ignore-blanket"
        risk = RiskLevel.medium if codes else RiskLevel.high
        flags = [] if codes else ["blanket-ignore"]
        results.append(_make("ty", kind, comment.strip(), path, line, source_line, codes=codes, risk=risk, flags=flags))

    # --- nosemgrep ---
    m = _NOSEMGREP.search(comment)
    if m:
        rule = m.group("rule")
        kind = "nosemgrep-specific" if rule else "nosemgrep-blanket"
        codes = [rule] if rule else []
        risk = RiskLevel.high if rule else RiskLevel.critical
        flags = [] if rule else ["blanket-ignore"]
        results.append(
            _make("semgrep", kind, comment.strip(), path, line, source_line, codes=codes, risk=risk, flags=flags)
        )

    # --- autopep8: off/on ---
    if _AUTOPEP8_OFF.search(comment):
        sup = _make(
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
    elif _AUTOPEP8_ON.search(comment):
        if block_state.get("autopep8_off"):
            open_sup = block_state["autopep8_off"].pop()
            open_sup.end_line = line

    # --- yapf: disable/enable ---
    if _YAPF_DISABLE.search(comment):
        sup = _make(
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
    elif _YAPF_ENABLE.search(comment):
        if block_state.get("yapf_disable"):
            open_sup = block_state["yapf_disable"].pop()
            open_sup.end_line = line

    # --- NOSONAR ---
    if _NOSONAR.search(comment):
        results.append(
            _make(
                "sonar", "nosonar", "# NOSONAR", path, line, source_line, risk=RiskLevel.high, flags=["blanket-ignore"]
            )
        )

    # --- Suspicious free-text suppression phrases ---
    if _SUSPICIOUS.search(comment) and not results:
        # Only add if no specific suppression already matched this comment
        results.append(
            _make(
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


def _close_unclosed_blocks(block_state: dict[str, list[Suppression]]) -> None:
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

    for tok_type, tok_string, tok_start, _tok_end, _line in tokens:
        if tok_type != tokenize.COMMENT:
            continue
        line_no = tok_start[0]
        source_line = source_lines[line_no - 1] if line_no <= len(source_lines) else ""
        found = _match_comment(tok_string, path, line_no, source_line, block_state)
        results.extend(found)

    _close_unclosed_blocks(block_state)
    return results
