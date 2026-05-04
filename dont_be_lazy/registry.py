"""Registry of all known suppression tools, kinds, and patterns."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PatternEntry:
    tool: str
    kind: str
    example: str
    scope: str
    inline: bool  # True = inline comment; False = config file
    risk_default: str
    description: str


# ---------------------------------------------------------------------------
# Registry definition
# ---------------------------------------------------------------------------

_ENTRIES: list[PatternEntry] = [
    # Ruff / Flake8
    PatternEntry("ruff", "noqa-blanket", "# noqa", "line", True, "high", "Blanket noqa, suppresses all rules"),
    PatternEntry("ruff", "noqa-specific", "# noqa: F401", "line", True, "medium", "Specific noqa code(s)"),
    PatternEntry("ruff", "file-noqa", "# ruff: noqa", "file", True, "high", "File-wide ruff noqa"),
    PatternEntry(
        "ruff", "disable-block", "# ruff: disable[TRY003]", "block", True, "medium", "Ruff range disable block"
    ),
    PatternEntry(
        "ruff", "file-ignore", "# ruff: file-ignore[F401]", "file", True, "high", "Ruff file-ignore directive"
    ),
    PatternEntry(
        "ruff", "config-ignore", "lint.ignore = [...]", "config", False, "medium", "Ruff lint.ignore in config"
    ),
    PatternEntry(
        "ruff", "per-file-ignores", "per-file-ignores = {...}", "config", False, "medium", "Per-file rule ignores"
    ),
    PatternEntry(
        "ruff", "config-exclude", "exclude = [...]", "config", False, "medium", "Path exclusions in ruff config"
    ),
    PatternEntry("flake8", "noqa-blanket", "# noqa", "line", True, "high", "Blanket noqa"),
    PatternEntry("flake8", "noqa-specific", "# noqa: E501", "line", True, "medium", "Specific noqa code(s)"),
    PatternEntry("flake8", "file-noqa", "# flake8: noqa", "file", True, "critical", "File-wide flake8 noqa"),
    PatternEntry("flake8", "per-file-ignores", "per-file-ignores = ...", "config", False, "medium", "Per-file ignores"),
    PatternEntry("flake8", "config-ignore", "ignore = E203", "config", False, "medium", "Global rule ignore"),
    PatternEntry("flake8", "config-exclude", "exclude = build,dist", "config", False, "medium", "Path exclusions"),
    # Pylint
    PatternEntry(
        "pylint", "disable-all", "# pylint: disable=all", "line", True, "critical", "Disable all pylint checks"
    ),
    PatternEntry(
        "pylint", "disable-line", "# pylint: disable=invalid-name", "line", True, "medium", "Line-level disable"
    ),
    PatternEntry(
        "pylint",
        "disable-block",
        "# pylint: disable=... / # pylint: enable=...",
        "block",
        True,
        "high",
        "Block disable",
    ),
    PatternEntry(
        "pylint", "disable-next", "# pylint: disable-next=...", "next-line", True, "medium", "Next-line disable"
    ),
    PatternEntry(
        "pylint", "config-disable", "disable = [...] in .pylintrc", "config", False, "high", "Global disable in config"
    ),
    # Mypy
    PatternEntry("mypy", "type-ignore-blanket", "# type: ignore", "line", True, "high", "Blanket type: ignore"),
    PatternEntry(
        "mypy", "type-ignore-specific", "# type: ignore[attr-defined]", "line", True, "medium", "Specific type: ignore"
    ),
    PatternEntry(
        "mypy", "file-ignore-errors", "# mypy: ignore-errors", "file", True, "critical", "File-wide mypy ignore"
    ),
    PatternEntry(
        "mypy",
        "ignore-missing-imports",
        "ignore_missing_imports = true",
        "config",
        False,
        "medium",
        "Ignore missing imports globally",
    ),
    PatternEntry(
        "mypy",
        "ignore-errors-config",
        "ignore_errors = true (overrides)",
        "config",
        False,
        "critical",
        "Ignore all errors for module",
    ),
    PatternEntry(
        "mypy",
        "config-disable-code",
        "disable_error_code = [...]",
        "config",
        False,
        "medium",
        "Disable specific error codes",
    ),
    # Pyright
    PatternEntry("pyright", "ignore-blanket", "# pyright: ignore", "line", True, "high", "Blanket pyright ignore"),
    PatternEntry(
        "pyright",
        "ignore-specific",
        "# pyright: ignore[reportUnknownMemberType]",
        "line",
        True,
        "medium",
        "Specific pyright ignore",
    ),
    PatternEntry(
        "pyright",
        "type-checking-off",
        "typeCheckingMode = off",
        "config",
        False,
        "critical",
        "Disable all type checking",
    ),
    PatternEntry(
        "pyright",
        "diagnostic-none",
        "reportMissingImports = none",
        "config",
        False,
        "medium",
        "Silence specific diagnostic",
    ),
    # Pytype
    PatternEntry(
        "pytype", "disable-block", "# pytype: disable=attribute-error", "block", True, "medium", "Pytype block disable"
    ),
    PatternEntry(
        "pytype", "config-disable", "disable = attribute-error", "config", False, "medium", "Pytype global disable"
    ),
    # ty (Astral)
    PatternEntry("ty", "ignore-blanket", "# ty: ignore", "line", True, "high", "Blanket ty ignore"),
    PatternEntry("ty", "ignore-specific", "# ty: ignore[rule-name]", "line", True, "medium", "Specific ty ignore"),
    # Bandit
    PatternEntry("bandit", "nosec-blanket", "# nosec", "line", True, "critical", "Blanket nosec"),
    PatternEntry("bandit", "nosec-specific", "# nosec B602", "line", True, "high", "Specific nosec code"),
    PatternEntry("bandit", "config-skip", "skips = [B101]", "config", False, "high", "Skip bandit checks in config"),
    PatternEntry(
        "bandit", "config-exclude", "exclude_dirs = [tests]", "config", False, "medium", "Exclude dirs from bandit"
    ),
    # Semgrep
    PatternEntry("semgrep", "nosemgrep-blanket", "# nosemgrep", "line", True, "critical", "Blanket nosemgrep"),
    PatternEntry(
        "semgrep", "nosemgrep-specific", "# nosemgrep: rule.name", "line", True, "high", "Specific nosemgrep rule"
    ),
    # Secrets
    PatternEntry(
        "secrets", "allowlist-secret", "# pragma: allowlist secret", "line", True, "high", "Allowlist a detected secret"
    ),
    # Black
    PatternEntry("black", "fmt-skip", "# fmt: skip", "line", True, "low", "Skip formatting on line"),
    PatternEntry(
        "black", "fmt-off-block", "# fmt: off / # fmt: on", "block", True, "medium", "Disable formatting block"
    ),
    PatternEntry(
        "black", "fmt-off-unclosed", "# fmt: off (no matching on)", "block", True, "high", "Unclosed fmt: off block"
    ),
    # isort
    PatternEntry("isort", "skip-line", "# isort: skip", "line", True, "low", "Skip isort on line"),
    PatternEntry("isort", "skip-file", "# isort: skip_file", "file", True, "medium", "Skip isort for entire file"),
    PatternEntry(
        "isort", "isort-off-block", "# isort: off / # isort: on", "block", True, "medium", "Disable isort block"
    ),
    PatternEntry("isort", "honor-noqa", "honor_noqa = true", "config", False, "medium", "isort honors noqa comments"),
    PatternEntry("isort", "config-skip", "skip = [...]", "config", False, "medium", "Paths skipped by isort"),
    PatternEntry(
        "isort", "config-skip-glob", "skip_glob = [...]", "config", False, "medium", "Glob patterns skipped by isort"
    ),
    # autopep8
    PatternEntry(
        "autopep8",
        "autopep8-off-block",
        "# autopep8: off / # autopep8: on",
        "block",
        True,
        "medium",
        "Disable autopep8 block",
    ),
    # yapf
    PatternEntry(
        "yapf", "yapf-disable-block", "# yapf: disable / # yapf: enable", "block", True, "medium", "Disable yapf block"
    ),
    # coverage
    PatternEntry("coverage", "no-cover", "# pragma: no cover", "line", True, "medium", "Exclude line from coverage"),
    PatternEntry("coverage", "no-branch", "# pragma: no branch", "line", True, "low", "Exclude branch from coverage"),
    PatternEntry("coverage", "omit-broad", "omit = [...]", "config", False, "critical", "Omit paths from coverage"),
    PatternEntry(
        "coverage",
        "exclude-lines-broad",
        "exclude_lines = [...]",
        "config",
        False,
        "high",
        "Exclude line patterns from coverage",
    ),
    # pytest
    PatternEntry("pytest", "skip-unconditional", "@pytest.mark.skip", "test", True, "high", "Unconditional test skip"),
    PatternEntry(
        "pytest", "skip-with-reason", "@pytest.mark.skip(reason=...)", "test", True, "medium", "Test skip with reason"
    ),
    PatternEntry(
        "pytest", "skipif-with-reason", "@pytest.mark.skipif(...)", "test", True, "low", "Conditional test skip"
    ),
    PatternEntry("pytest", "xfail-nonstrict", "@pytest.mark.xfail", "test", True, "medium", "Non-strict xfail"),
    PatternEntry("pytest", "xfail-strict", "@pytest.mark.xfail(strict=True)", "test", True, "low", "Strict xfail"),
    PatternEntry("pytest", "skip-call", "pytest.skip(...)", "test", True, "medium", "Imperative pytest.skip"),
    PatternEntry("pytest", "xfail-call", "pytest.xfail(...)", "test", True, "medium", "Imperative pytest.xfail"),
    PatternEntry(
        "pytest", "addopts-marker", "addopts = -m 'not slow'", "config", False, "high", "Marker filter excludes tests"
    ),
    # unittest
    PatternEntry(
        "unittest", "skip-unconditional", "@unittest.skip(...)", "test", True, "high", "Unconditional unittest skip"
    ),
    PatternEntry(
        "unittest", "skip-conditional", "@unittest.skipIf(...)", "test", True, "medium", "Conditional unittest skip"
    ),
    PatternEntry("unittest", "skip-test-call", "self.skipTest(...)", "test", True, "medium", "Imperative skipTest"),
    PatternEntry(
        "unittest", "raise-skip-test", "raise unittest.SkipTest(...)", "test", True, "medium", "Raise SkipTest"
    ),
    # hypothesis
    PatternEntry(
        "hypothesis",
        "suppress-health-check",
        "@settings(suppress_health_check=[...])",
        "test",
        True,
        "medium",
        "Suppress hypothesis health check",
    ),
    PatternEntry(
        "hypothesis", "deadline-none", "@settings(deadline=None)", "test", True, "medium", "Remove hypothesis deadline"
    ),
    # vulture
    PatternEntry("vulture", "whitelist-file", "vulture_whitelist.py", "file", False, "high", "Vulture whitelist file"),
    PatternEntry(
        "vulture", "ignore-names", "ignore_names = [...]", "config", False, "medium", "Ignore names from dead-code scan"
    ),
    PatternEntry(
        "vulture", "ignore-decorators", "ignore_decorators = [...]", "config", False, "medium", "Ignore decorated names"
    ),
    # pip-audit / safety
    PatternEntry(
        "pip-audit",
        "ignored-vulnerability",
        "ignore-vulns = [PYSEC-...]",
        "config",
        False,
        "critical",
        "Ignored vulnerability",
    ),
    PatternEntry(
        "safety", "ignored-vulnerability", "ignore: {id: ...}", "config", False, "critical", "Ignored vulnerability"
    ),
    # pydocstyle / pydoclint
    PatternEntry(
        "pydocstyle", "config-ignore", "ignore = [D100, D104]", "config", False, "medium", "Ignored doc rules"
    ),
    PatternEntry("pydoclint", "config-ignore", "ignore = [DOC201]", "config", False, "medium", "Ignored doc rules"),
    # sonar
    PatternEntry("sonar", "nosonar", "# NOSONAR", "line", True, "high", "Suppress SonarQube finding"),
    # unknown
    PatternEntry(
        "unknown",
        "suspicious-comment",
        "# ignore this / # disable check",
        "line",
        True,
        "low",
        "Suspicious suppression-like comment",
    ),
]

_BY_TOOL: dict[str, list[PatternEntry]] = {}
for _e in _ENTRIES:
    _BY_TOOL.setdefault(_e.tool, []).append(_e)


def all_tools() -> list[str]:
    return sorted(_BY_TOOL.keys())


def entries_for_tool(tool: str | None = None) -> list[PatternEntry]:
    if tool:
        return _BY_TOOL.get(tool, [])
    return _ENTRIES


def inline_entries(tool: str | None = None) -> list[PatternEntry]:
    return [e for e in entries_for_tool(tool) if e.inline]


def config_entries(tool: str | None = None) -> list[PatternEntry]:
    return [e for e in entries_for_tool(tool) if not e.inline]
