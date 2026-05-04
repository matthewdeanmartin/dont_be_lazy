# `dont_be_lazy` CLI spec

## Purpose

`dont_be_lazy` is a Python repo audit tool that finds suppressions, ignores, skips, xfails, exclusions, and “please don’t check this” directives across a codebase **without importing or running the suppressed tool**.

It answers:

> “Where did we silence a tool, skip a test, exclude coverage, or opt out of a checker, and is that suppression broad, stale, unexplained, or worth revisiting?”

It should be safe to run occasionally in CI, locally, or as a scheduled audit.

Primary design constraint: **static discovery only**. `dont_be_lazy` parses files and config; it does not execute `pytest`, `ruff`, `mypy`, `bandit`, etc. That avoids dependency/version/plugin hell.

---

# Core model

Each finding is a `Suppression`.

```json
{
  "id": "DBL001234",
  "tool": "mypy",
  "kind": "inline-ignore",
  "pattern": "# type: ignore[attr-defined]",
  "path": "src/pkg/module.py",
  "line": 42,
  "end_line": 42,
  "scope": "line",
  "codes": ["attr-defined"],
  "reason": null,
  "age": {
    "first_seen": "2024-02-11",
    "last_modified": "2025-12-09",
    "git_author": "Jane Dev"
  },
  "risk": "medium",
  "flags": ["no-reason", "specific-code"],
  "text": "from legacy import thing  # type: ignore[attr-defined]"
}
```

`dont_be_lazy` should classify suppressions by:

| Field    | Meaning                                                                             |
| -------- | ----------------------------------------------------------------------------------- |
| `tool`   | Tool family: `ruff`, `flake8`, `mypy`, `pytest`, `coverage`, etc.                   |
| `kind`   | Specific mechanism: `noqa`, `type-ignore`, `pylint-disable`, `pytest-skip`, etc.    |
| `scope`  | `line`, `next-line`, `block`, `file`, `module`, `config`, `path`, `test`, `unknown` |
| `codes`  | Suppressed rule/error codes when statically available                               |
| `reason` | Reason extracted from arguments/comments/config when available                      |
| `risk`   | `low`, `medium`, `high`, `critical`                                                 |
| `flags`  | Machine-readable issues: `blanket-ignore`, `no-reason`, `file-wide`, `stale`, etc.  |

---

# CLI

## Top-level command

```bash
dont_be_lazy [OPTIONS] COMMAND [ARGS]
```

Global options:

```bash
--root PATH                  Repo root. Default: auto-detect git root, else cwd.
--config PATH                Config file. Default: discover pyproject.toml, dont_be_lazy.toml, .dont-be-lazy.toml.
--include GLOB               Include paths. Repeatable.
--exclude GLOB               Exclude paths. Repeatable.
--respect-gitignore / --no-respect-gitignore
                             Default: respect .gitignore.
--follow-symlinks            Default: false.
--jobs N                     Parallel file scanning. Default: CPU count.
--encoding ENCODING          Default: utf-8 with fallback.
--stdin                      Read file list from stdin.
--no-color
-v, --verbose
-q, --quiet
--version
```

---

# Subcommands

## 1. `scan`

Main audit command.

```bash
dont_be_lazy scan [PATHS...]
```

Find all supported suppressions in code and config.

Common examples:

```bash
dont_be_lazy scan
dont_be_lazy scan src tests
dont_be_lazy scan --format table
dont_be_lazy scan --format json --output suppressions.json
dont_be_lazy scan --fail-on high
dont_be_lazy scan --fail-on-stale 180d
```

Options:

```bash
--format table|json|jsonl|sarif|markdown
                             Default: table.
--output PATH                Write output to file.
--tool TOOL                  Limit to one or more tools. Repeatable.
--kind KIND                  Limit to specific suppression kind. Repeatable.
--scope SCOPE                Limit by scope: line, block, file, config, test.
--risk low|medium|high|critical
                             Show findings at or above risk.
--fail-on low|medium|high|critical
                             Exit nonzero if findings at or above risk exist.
--fail-on-count N            Exit nonzero if finding count exceeds N.
--fail-on-stale AGE          Exit nonzero if suppressions older than AGE exist.
--require-reason             Flag suppressions without an extracted reason.
--min-age AGE                Only show suppressions older than AGE.
--since REF                  Use git diff against REF; scan changed files/lines.
--baseline PATH              Existing baseline file.
--update-baseline PATH       Rewrite baseline with current findings.
--new-only                   Only show suppressions not in baseline.
--with-git-blame             Attach author/date using git blame.
--with-git-history           Estimate first-seen date using git log -S/-G.
--no-config-suppressions     Skip config file suppressions.
--no-test-suppressions       Skip skipped/xfail tests.
--show-context N             Include N lines of source context.
```

Exit codes:

| Code | Meaning                                 |
| ---: | --------------------------------------- |
|  `0` | Completed, no fail condition triggered  |
|  `1` | Findings triggered a configured failure |
|  `2` | CLI/config error                        |
|  `3` | Parse/read error exceeded tolerance     |
|  `4` | Internal error                          |

---

## 2. `summary`

High-level counts for review.

```bash
dont_be_lazy summary
```

Example output:

```text
Suppression summary

Tool        Count   High risk   Stale >180d   No reason
ruff        241     19          88            203
mypy        74      11          39            62
pytest      32      7           14            5
coverage    18      4           9             16
bandit      9       6           5             9

Total: 374 suppressions
Highest-risk category: blanket security suppressions
```

Options:

```bash
--by tool|kind|scope|path|owner|age|risk
--format table|json|markdown
--with-git-blame
--top N
```

---

## 3. `list`

List known suppression patterns.

```bash
dont_be_lazy list tools
dont_be_lazy list checks
dont_be_lazy list checks --tool mypy
dont_be_lazy list patterns --tool pytest
```

This is the “what do you know how to find?” command.

Options:

```bash
--tool TOOL
--format table|json|markdown
--include-nonstandard
--only-config
--only-inline
```

---

## 4. `config-suppressions`

Separate command for config-level ignores, per your note.

```bash
dont_be_lazy config-suppressions
```

Finds suppressions that are not inline comments, such as:

```toml
[tool.ruff.lint]
ignore = ["E501", "B008"]

[tool.mypy]
disable_error_code = ["import-untyped"]

[tool.pytest.ini_options]
addopts = "-m 'not slow'"
```

Options:

```bash
--tool TOOL
--format table|json|markdown
--include-defaults           Include tool defaults when inferable from config.
--nonstandard-only           Show project-specific or custom suppressions only.
--explain                    Explain likely effect of each config suppression.
```

Behavior:

* Parse `pyproject.toml`, `setup.cfg`, `tox.ini`, `.flake8`, `.pylintrc`, `mypy.ini`, `pytest.ini`, `.coveragerc`, `ruff.toml`, `.ruff.toml`, `pyrightconfig.json`, `bandit.yaml`, `.bandit`, `isort.cfg`, etc.
* Do not validate by running the owning tool.
* Report keys that disable rules, exclude paths, ignore files, ignore codes, omit coverage, skip tests, or weaken diagnostics.

---

## 5. `stale`

Prioritize old suppressions.

```bash
dont_be_lazy stale --older-than 180d
```

Options:

```bash
--older-than AGE             Default: 180d.
--with-git-blame             Use line blame.
--with-git-history           Try to find first commit introducing suppression.
--format table|json|markdown
--group-by owner|tool|path|risk
```

Age strategy:

1. If baseline has `first_seen`, use it.
2. Else if `--with-git-history`, search git history for the suppression text.
3. Else if `--with-git-blame`, use blame date for the line.
4. Else mark age as unknown.

---

## 6. `owners`

Show suppressions by author/team.

```bash
dont_be_lazy owners --with-git-blame
```

Options:

```bash
--owner-map PATH             CODEOWNERS-like owner map.
--group-by author|email|team|path
--format table|json|markdown
```

---

## 7. `explain`

Explain a finding.

```bash
dont_be_lazy explain src/foo.py:42
dont_be_lazy explain DBL001234
```

Output should include:

* Matched tool.
* Why it is considered a suppression.
* Scope.
* Risk rationale.
* Suggested human review prompt.
* Whether it is blanket or code-specific.

Example:

```text
src/foo.py:42

Matched: mypy # type: ignore[attr-defined]
Scope: line
Risk: medium

Why:
  This suppresses a specific mypy error code on one line.

Review:
  - Is attr-defined still necessary?
  - Is the imported object now typed?
  - Can this be replaced with a stub, Protocol, cast, or better annotation?
```

---

## 8. `baseline`

Manage accepted suppressions.

```bash
dont_be_lazy baseline create --output .dont-be-lazy-baseline.json
dont_be_lazy baseline check --baseline .dont-be-lazy-baseline.json
dont_be_lazy baseline prune --baseline .dont-be-lazy-baseline.json
```

Behavior:

* Baseline stores stable fingerprints, not only line numbers.
* Fingerprint should include normalized file path, suppression kind, codes, nearby source hash, and normalized comment text.
* `new-only` mode reports suppressions not present in baseline.

---

## 9. `rules`

Manage policy rules.

```bash
dont_be_lazy rules list
dont_be_lazy rules test
```

Example rules:

```toml
[tool.dont_be_lazy.policy]
fail_on = "high"
max_suppressions = 500
require_reason = true
stale_after = "180d"

[tool.dont_be_lazy.policy.by_tool.bandit]
fail_on = "medium"
require_codes = true

[tool.dont_be_lazy.policy.by_kind.blanket_noqa]
risk = "high"
```

---

# Output formats

## Human table

```text
Risk  Tool      Scope  Path              Line  Suppression
HIGH  bandit    line   src/auth.py       88    # nosec
HIGH  ruff      file   src/legacy.py     1     # ruff: noqa
MED   mypy      line   src/api.py        44    # type: ignore[attr-defined]
LOW   black     block  src/generated.py  10    # fmt: off ... # fmt: on
```

## JSON

Stable, documented schema.

```json
{
  "version": "1.0",
  "root": "/repo",
  "generated_at": "2026-05-03T12:00:00Z",
  "summary": {
    "total": 374,
    "by_tool": {
      "ruff": 241,
      "mypy": 74
    }
  },
  "findings": []
}
```

## SARIF

Optional but useful for GitHub code scanning.

```bash
dont_be_lazy scan --format sarif --output dont-be-lazy.sarif
```

---

# Supported suppressions and checks

## Python linter suppressions

### Ruff

Supported inline/file patterns:

```python
x = 1  # noqa
x = 1  # noqa: F401,E501
# ruff: noqa
# ruff: noqa: F401
# ruff: noqa: F401, E501
# ruff: noqa
# ruff: noqa: T201
# ruff: noqa: F401,E501
# ruff: noqa
```

Also support newer Ruff-specific range and file ignore directives:

```python
# ruff: disable[TRY003]
...
# ruff: enable[TRY003]

# ruff: file-ignore[F401, E501]
```

Ruff documents `# noqa`, `# ruff: noqa`, range-style `# ruff: disable[...]` / `# ruff: enable[...]`, and `# ruff: file-ignore[...]` suppression forms. ([Astral Docs][1])

Config suppressions:

```toml
[tool.ruff.lint]
ignore = ["E501"]
extend-ignore = ["B008"]
per-file-ignores = { "__init__.py" = ["F401"] }

[tool.ruff]
exclude = ["generated/"]
extend-exclude = ["legacy/"]
```

Ruff config discovery and settings live in `pyproject.toml`, `ruff.toml`, and `.ruff.toml`; Ruff’s own docs describe closest-config behavior and `[tool.ruff]` discovery. ([Astral Docs][2])

Risk suggestions:

| Pattern                      | Risk                         |
| ---------------------------- | ---------------------------- |
| `# noqa` with no code        | high                         |
| `# ruff: noqa` file-wide     | high                         |
| `# ruff: disable[...]` block | medium/high depending length |
| Specific code line ignore    | low/medium                   |
| `per-file-ignores`           | medium/high                  |

---

### Flake8

Supported:

```python
x = 1  # noqa
x = 1  # noqa: F401
# flake8: noqa
```

Flake8 supports `# noqa` to silence messages on specific lines and `# flake8: noqa` to ignore an entire file. ([Flake8][3])

Config suppressions:

```ini
[flake8]
ignore = E203,W503
extend-ignore = B950
per-file-ignores =
    __init__.py:F401
exclude =
    build,
    dist,
    generated
```

Special detection:

* malformed `# noqa F401`
* malformed `# noqa : F401`
* blanket `# noqa`
* file-wide `# flake8: noqa`
* duplicate comments like `# noqa # noqa`

Risk:

| Pattern                          | Risk                   |
| -------------------------------- | ---------------------- |
| `# noqa` no code                 | high                   |
| malformed intended-specific noqa | high                   |
| `# flake8: noqa`                 | critical for file-wide |
| `per-file-ignores`               | medium/high            |

---

### Pylint

Supported:

```python
# pylint: disable=unused-argument
# pylint: enable=unused-argument
# pylint: disable-next=unused-argument
x = 1  # pylint: disable=invalid-name
```

Pylint’s message-control docs describe single-line, next-line, scope, block, and file/module disable/enable pragmas. ([Pylint][4])

Config suppressions:

```ini
[MESSAGES CONTROL]
disable =
    missing-docstring,
    too-few-public-methods
enable =
```

```toml
[tool.pylint.messages_control]
disable = ["missing-docstring"]
```

Risk:

| Pattern                         | Risk       |
| ------------------------------- | ---------- |
| `disable=all`                   | critical   |
| module-level disable            | high       |
| block disable without enable    | high       |
| line-specific disable with code | low/medium |

---

## Type checker suppressions

### Mypy / standard typing directive

Supported:

```python
x = thing  # type: ignore
x = thing  # type: ignore[attr-defined]
# type: ignore
```

The Python typing spec defines `# type: ignore` as a special comment for silencing type checker errors, and mypy supports code-specific forms like `# type: ignore[attr-defined]`. ([Typing Documentation][5])

Also detect file/module-level patterns:

```python
# mypy: ignore-errors
# mypy: disable-error-code=attr-defined, import-untyped
# mypy: allow-any-generics
```

Config suppressions:

```ini
[mypy]
ignore_missing_imports = True
disable_error_code = import-untyped
exclude = generated

[mypy-some_package.*]
ignore_errors = True
ignore_missing_imports = True
```

```toml
[tool.mypy]
ignore_missing_imports = true
disable_error_code = ["import-untyped"]

[[tool.mypy.overrides]]
module = ["legacy.*"]
ignore_errors = true
```

Risk:

| Pattern                         | Risk        |
| ------------------------------- | ----------- |
| `# type: ignore` no code        | high        |
| file-level `# type: ignore`     | critical    |
| `ignore_errors = true`          | critical    |
| `ignore_missing_imports = true` | medium/high |
| specific `type: ignore[code]`   | low/medium  |

---

### Pyright / Basedpyright

Supported:

```python
x = thing  # pyright: ignore
x = thing  # pyright: ignore[reportUnknownMemberType]
x = thing  # type: ignore
```

Pyright-family tools support `# pyright: ignore`, and Basedpyright explicitly prefers `# pyright: ignore` over `# type: ignore` because it is stricter. ([BasedPyright][6])

Config suppressions:

```json
{
  "typeCheckingMode": "off",
  "exclude": ["generated"],
  "ignore": ["legacy"],
  "reportMissingImports": "none",
  "reportUnknownMemberType": "none",
  "enableTypeIgnoreComments": false
}
```

Risk:

| Pattern                                | Risk        |
| -------------------------------------- | ----------- |
| `# pyright: ignore` no diagnostic code | high        |
| `typeCheckingMode = off`               | critical    |
| diagnostic set to `none`               | medium/high |
| specific `pyright: ignore[rule]`       | low/medium  |

---

### Pytype

Supported:

```python
x = a.foo  # pytype: disable=attribute-error

# pytype: disable=attribute-error
...
# pytype: enable=attribute-error

x = a.foo  # type: ignore
```

Pytype documents `pytype: disable=error-class` and matching block disable/enable comments, while recommending precise `pytype: disable=...` over catch-all `type: ignore`. ([Google GitHub][7])

Config suppressions:

```ini
[pytype]
disable = attribute-error
exclude = generated
```

Risk:

| Pattern                         | Risk       |
| ------------------------------- | ---------- |
| `# type: ignore`                | high       |
| block disable without enable    | high       |
| specific `pytype: disable=code` | low/medium |

---

### Astral `ty`

Supported:

```python
x = thing  # ty: ignore
x = thing  # ty: ignore[rule-name]
x = thing  # type: ignore
```

Config suppressions:

```toml
[tool.ty]
respect-type-ignore-comments = true
```

Astral’s `ty` config documents `respect-type-ignore-comments`; if false, `type: ignore` is treated as a normal comment and users must use `ty: ignore` instead. ([Astral Docs][8])

Risk:

| Pattern                        | Risk        |
| ------------------------------ | ----------- |
| `ty: ignore` without code      | high        |
| `type: ignore` respected by ty | medium/high |
| specific `ty: ignore[...]`     | low/medium  |

---

## Security suppressions

### Bandit

Supported:

```python
subprocess.call(cmd, shell=True)  # nosec
subprocess.call(cmd, shell=True)  # nosec B602
subprocess.call(cmd, shell=True)  # nosec B602,B607
```

Bandit uses `# nosec` to skip security checks on a line; Bandit also supports config and CLI skip mechanisms for test IDs. ([Bandit][9])

Config suppressions:

```yaml
skips:
  - B101
  - B602

exclude_dirs:
  - tests
  - generated
```

```toml
[tool.bandit]
skips = ["B101"]
exclude_dirs = ["tests"]
```

Risk:

| Pattern                  | Risk          |
| ------------------------ | ------------- |
| `# nosec` no code        | critical      |
| security skip in config  | high/critical |
| `# nosec Bxxx`           | medium/high   |
| skipping `B101` in tests | medium        |

---

### Semgrep

Supported:

```python
# nosemgrep
# nosemgrep: python.lang.security.audit.dangerous-subprocess-use
```

Config suppressions:

```yaml
paths:
  exclude:
    - generated
    - vendor
```

Risk:

| Pattern                   | Risk        |
| ------------------------- | ----------- |
| `# nosemgrep` no rule     | critical    |
| file/path exclusion       | high        |
| specific rule suppression | medium/high |

---

### Detect-secrets / secret scanners

Supported:

```python
password = "..."  # pragma: allowlist secret
password = "..."  # pragma: whitelist secret
```

Config suppressions:

```json
{
  "exclude": {
    "files": "tests/fixtures"
  },
  "plugins_used": []
}
```

Risk:

| Pattern                       | Risk          |
| ----------------------------- | ------------- |
| allowlisted secret            | high/critical |
| broad file exclude            | high          |
| fixture allowlist with reason | medium        |

---

## Formatter/import suppressions

### Black

Supported:

```python
x = very_long_call(...)  # fmt: skip

# fmt: off
...
# fmt: on
```

Black documents `# fmt: skip` for a line and `# fmt: off` / `# fmt: on` for blocks. It also allows `fmt: skip` to be combined with other pragmas. ([Black][10])

Risk:

| Pattern               | Risk   |
| --------------------- | ------ |
| `fmt: skip`           | low    |
| long `fmt: off` block | medium |
| unclosed `fmt: off`   | high   |

---

### isort

Supported:

```python
import z  # isort: skip
# isort: skip_file
# isort: off
...
# isort: on
```

Also detect when `isort` is configured to honor `noqa`:

```toml
[tool.isort]
honor_noqa = true
skip = ["generated"]
skip_glob = ["*_pb2.py"]
```

isort documents `honor_noqa` as a setting that tells isort to honor `noqa` comments. ([PycQA][11])

Risk:

| Pattern                  | Risk        |
| ------------------------ | ----------- |
| `isort: skip`            | low         |
| `isort: skip_file`       | medium      |
| broad `skip`/`skip_glob` | medium/high |

---

### Autopep8 / yapf

Supported:

```python
# autopep8: off
...
# autopep8: on

# yapf: disable
...
# yapf: enable
```

Risk:

| Pattern           | Risk        |
| ----------------- | ----------- |
| block disable     | low/medium  |
| unclosed disable  | high        |
| file-wide disable | medium/high |

---

## Coverage suppressions

### coverage.py

Supported:

```python
if debug:  # pragma: no cover
    ...

if impossible:  # pragma: no branch
    ...
```

coverage.py documents `# pragma: no cover` as a built-in exclusion and `# pragma: no branch` for branch coverage exclusions. ([Coverage][12])

Config suppressions:

```ini
[run]
omit =
    tests/*
    generated/*

[report]
exclude_lines =
    pragma: no cover
    if TYPE_CHECKING:
    raise NotImplementedError
```

```toml
[tool.coverage.run]
omit = ["tests/*", "generated/*"]

[tool.coverage.report]
exclude_lines = [
  "pragma: no cover",
  "if TYPE_CHECKING:",
]
```

Risk:

| Pattern                                  | Risk        |
| ---------------------------------------- | ----------- |
| `pragma: no cover` on function/class def | medium/high |
| `pragma: no cover` on defensive branch   | low/medium  |
| `omit = src/*`                           | critical    |
| custom broad `exclude_lines`             | high        |

---

## Test suppressions

### Pytest

Supported decorators:

```python
@pytest.mark.skip
@pytest.mark.skip(reason="broken on CI")
@pytest.mark.skipif(sys.platform == "win32", reason="...")
@pytest.mark.xfail
@pytest.mark.xfail(reason="bug #123")
@pytest.mark.xfail(strict=False)
```

Supported imperative calls:

```python
pytest.skip("reason")
pytest.xfail("reason")
```

Pytest documents `@pytest.mark.skip`, `@pytest.mark.skipif`, `pytest.skip(...)`, `@pytest.mark.xfail`, and `pytest.xfail(...)` for skipped and expected-failure tests. ([pytest][13])

Config suppressions:

```ini
[pytest]
addopts = -m "not slow"
markers =
    slow: skipped in normal CI
```

```toml
[tool.pytest.ini_options]
addopts = "-m 'not integration'"
```

Detection behavior:

* Parse AST for decorators and calls.
* Extract static `reason=` string when possible.
* Flag dynamic/unknown reasons.
* Flag unconditional skips.
* Flag `xfail(strict=False)` as higher risk than `strict=True`.
* Flag tests skipped by marker selection in `addopts`.

Risk:

| Pattern                          | Risk                         |
| -------------------------------- | ---------------------------- |
| unconditional `skip` no reason   | high                         |
| unconditional `skip` with reason | medium                       |
| `skipif` with reason             | low/medium                   |
| `xfail(strict=False)`            | medium/high                  |
| `xfail(strict=True)`             | low/medium                   |
| `addopts = -m "not ..."`         | high if excludes large class |

---

### unittest

Supported:

```python
@unittest.skip("reason")
@unittest.skipIf(condition, "reason")
@unittest.skipUnless(condition, "reason")
raise unittest.SkipTest("reason")
self.skipTest("reason")
```

Risk:

| Pattern            | Risk        |
| ------------------ | ----------- |
| unconditional skip | medium/high |
| conditional skip   | low/medium  |
| no reason          | high        |

---

### Hypothesis

Supported:

```python
from hypothesis import settings

@settings(suppress_health_check=[HealthCheck.too_slow])
@settings(deadline=None)
```

Risk:

| Pattern                        | Risk   |
| ------------------------------ | ------ |
| suppressed health checks       | medium |
| `deadline=None`                | medium |
| broad profile disabling checks | high   |

---

## Documentation/docstring suppressions

### pydocstyle / doc8 / pydoclint

Supported:

```python
def f():  # noqa: D401
    """..."""

def g():  # noqa: DOC201
    """..."""
```

pydoclint supports `# noqa: DOC...`-style suppressions compatible with Flake8/Ruff syntax. ([JSH9][14])

Config suppressions:

```toml
[tool.pydocstyle]
ignore = ["D100", "D104"]

[tool.pydoclint]
ignore = ["DOC201"]
```

Risk:

| Pattern                   | Risk        |
| ------------------------- | ----------- |
| blanket doc ignore        | medium      |
| specific doc rule         | low         |
| file-wide doc suppression | medium/high |

---

## Dead-code tools

### Vulture

Supported:

```python
x = unused  # noqa: F841
import unused  # noqa: F401
```

Vulture supports Flake8-compatible `# noqa: F401` and `# noqa: F841` for unused imports and unused local variables, though its docs recommend whitelists instead of noqa comments. ([PyPI][15])

Config suppressions / whitelist files:

```toml
[tool.vulture]
exclude = ["generated"]
ignore_decorators = ["@app.route", "@validator"]
ignore_names = ["visit_*"]
```

Also detect likely whitelist files:

```text
vulture_whitelist.py
whitelist.py
dead_code_whitelist.py
```

Risk:

| Pattern                | Risk       |
| ---------------------- | ---------- |
| `ignore_names = ["*"]` | critical   |
| broad whitelist file   | high       |
| specific `F401`/`F841` | low/medium |

---

## Packaging / dependency / audit suppressions

### pip-audit

Config/file suppressions:

```toml
[tool.pip-audit]
ignore-vulns = ["PYSEC-..."]
```

Risk:

| Pattern                         | Risk     |
| ------------------------------- | -------- |
| ignored vulnerability           | critical |
| ignored vuln with expiry/reason | high     |

---

### Safety

Supported config suppressions:

```yaml
ignore:
  12345:
    reason: "..."
    expires: "2026-06-01"
```

Risk:

| Pattern                           | Risk     |
| --------------------------------- | -------- |
| ignored vulnerability no expiry   | critical |
| ignored vulnerability with expiry | high     |

---

## General source comments

Catch-all known suppression tokens:

```text
noqa
NOQA
nosec
NOSONAR
noqa: ...
type: ignore
pyright: ignore
pytype: disable
pylint: disable
fmt: off
fmt: skip
isort: skip
isort: skip_file
pragma: no cover
pragma: no branch
no semgrep / nosemgrep
allowlist secret
whitelist secret
skip
xfail
```

Unknown suppression detector should also catch suspicious phrases in comments:

```text
ignore this
disable check
suppress warning
skip lint
TODO fix lint
temporary ignore
lazy
hack: ignore
```

These should be reported as `tool = unknown`, `kind = suspicious-comment`, risk `low` by default, unless they match stronger patterns.

---

# Risk scoring

Default risk algorithm:

```text
risk = base(tool, kind)
     + scope_weight
     + blanket_weight
     + no_reason_weight
     + stale_weight
     + security_weight
     + config_weight
     - specificity_credit
     - expiry_credit
```

Suggested factors:

| Signal                    | Effect   |
| ------------------------- | -------- |
| Security suppression      | increase |
| File-wide suppression     | increase |
| Config-wide suppression   | increase |
| No rule/error code        | increase |
| No reason                 | increase |
| Older than threshold      | increase |
| Has expiry date           | decrease |
| Specific code/rule        | decrease |
| Test skip with issue link | decrease |
| Generated/vendor path     | decrease |

Risk levels:

| Risk       | Meaning                                                               |
| ---------- | --------------------------------------------------------------------- |
| `low`      | Likely benign, but visible                                            |
| `medium`   | Worth periodic review                                                 |
| `high`     | Broad, stale, unexplained, or likely hiding real issues               |
| `critical` | Security/type/lint suppression at broad scope or vulnerability ignore |

---

# Reason extraction

`dont_be_lazy` should attempt to extract reasons from:

```python
# noqa: F401  # re-export public API
# type: ignore[attr-defined]  # third-party lib lacks stubs
@pytest.mark.skip(reason="requires paid API")
@pytest.mark.xfail(reason="bug #123", strict=True)
pytest.skip("not supported on Windows")
```

Reason fields:

```json
{
  "reason": "third-party lib lacks stubs",
  "reason_source": "trailing-comment",
  "reason_quality": "plain-text"
}
```

Reason quality:

| Value         | Meaning                                          |
| ------------- | ------------------------------------------------ |
| `none`        | No reason found                                  |
| `placeholder` | `todo`, `fix later`, `temporary`, `legacy`, etc. |
| `plain-text`  | Some explanatory text                            |
| `issue-link`  | Includes issue/ticket/URL                        |
| `expiry`      | Includes date or expiry marker                   |

Recognized expiry formats:

```text
expires: 2026-06-01
until: 2026-06-01
remove-after: 2026-06-01
TODO(#123)
FIXME: remove once ...
```

---

# Config file

Default discovery order:

1. Explicit `--config`.
2. `pyproject.toml` `[tool.dont_be_lazy]`.
3. `dont_be_lazy.toml`.
4. `.dont-be-lazy.toml`.
5. Built-in defaults.

Example:

```toml
[tool.dont_be_lazy]
include = ["src/**/*.py", "tests/**/*.py"]
exclude = [
  ".git/**",
  ".venv/**",
  "venv/**",
  "build/**",
  "dist/**",
  "**/__pycache__/**",
  "generated/**",
]
respect_gitignore = true
jobs = 8

[tool.dont_be_lazy.scan]
format = "table"
with_git_blame = false
show_context = 1

[tool.dont_be_lazy.policy]
fail_on = "high"
require_reason = false
stale_after = "180d"
max_suppressions = 1000

[tool.dont_be_lazy.policy.by_tool.bandit]
fail_on = "medium"
require_reason = true

[tool.dont_be_lazy.policy.by_tool.pytest]
require_reason = true

[tool.dont_be_lazy.generated]
paths = [
  "src/**/_pb2.py",
  "src/**/_pb2_grpc.py",
  "migrations/**",
]
risk_discount = true

[tool.dont_be_lazy.custom_patterns]
"internal-linter" = [
  '# internal-lint: disable',
  '# internal-lint: ignore',
]
```

---

# Nonstandard/custom suppressions

Custom pattern support should be first-class.

```toml
[tool.dont_be_lazy.custom_patterns."our_tool"]
patterns = [
  '(?P<token>#\\s*ourtool:\\s*ignore(?:\\[(?P<codes>[^\\]]+)\\])?)'
]
scope = "line"
risk = "medium"
```

For safety, custom regexes should:

* Be compiled once.
* Have timeout/complexity guard if possible.
* Support named groups:

  * `token`
  * `codes`
  * `reason`
  * `scope`
  * `tool`

---

# Parsing strategy

## File walking

Default scanned file types:

```text
.py
.pyi
.toml
.ini
.cfg
.yaml
.yml
.json
```

Optional:

```text
.md
.rst
.txt
```

Skip by default:

```text
.git/
.hg/
.svn/
.venv/
venv/
env/
node_modules/
dist/
build/
__pycache__/
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage*
```

## Python parsing

Use two layers:

1. **Token scanner** for comments.

   * Required for `# noqa`, `# type: ignore`, `# nosec`, etc.
   * Use `tokenize`, not regex-only, so comments inside strings are not false positives.

2. **AST scanner** for tests/decorators/calls.

   * Required for pytest/unittest skip/xfail.
   * Extract decorators, call names, keyword args, static strings.

Do not import modules.

## Config parsing

Use:

* `tomllib` for TOML on Python 3.11+.
* Fallback dependency optional for older Python, or require Python 3.11+.
* `configparser` for INI/CFG.
* JSON parser.
* YAML optional. If no YAML parser installed, degrade gracefully by regex scanning known simple keys or report “unparsed YAML”.

Recommended package stance:

```text
Core install should have zero heavy tool dependencies.
Optional extras are allowed for better config parsing, not tool execution.
```

Example:

```bash
pip install dont_be_lazy[yaml,sarif]
```

---

# Matching correctness

## Avoid false positives

Should not flag:

```python
text = "# noqa"
doc = """
Use # type: ignore here.
"""
```

Should flag:

```python
x = 1  # noqa
```

Because comments should be discovered via tokenizer.

## Multiple suppressions on one line

Should produce separate findings or one compound finding?

Recommended: one finding per suppression token, with shared `line`.

```python
x = f()  # type: ignore[attr-defined]  # noqa: F841  # nosec B101
```

Output:

* `mypy/type-ignore`
* `flake8/noqa`
* `bandit/nosec`

## Block matching

For block suppressions:

```python
# fmt: off
...
# fmt: on
```

Create:

```json
{
  "scope": "block",
  "line": 10,
  "end_line": 40,
  "flags": []
}
```

If no close marker:

```json
{
  "scope": "block",
  "end_line": null,
  "flags": ["unclosed-block-suppression"],
  "risk": "high"
}
```

## File-wide detection

Treat as file-wide when:

* Known file directive: `# flake8: noqa`, `# ruff: noqa`.
* Pylint disable at top-level before code/docstring.
* Mypy `# mypy: ignore-errors`.
* Config path exclusion covers file.
* Whole file omitted from coverage/lint config.

---

# Policy checks

Each finding can trigger policy rules:

| Rule ID  | Meaning                                            |
| -------- | -------------------------------------------------- |
| `DBL001` | Blanket inline suppression                         |
| `DBL002` | File-wide suppression                              |
| `DBL003` | Block suppression without matching enable          |
| `DBL004` | Suppression has no reason                          |
| `DBL005` | Suppression is stale                               |
| `DBL006` | Security suppression                               |
| `DBL007` | Type checker suppression                           |
| `DBL008` | Skipped test                                       |
| `DBL009` | Non-strict xfail                                   |
| `DBL010` | Config-level rule ignore                           |
| `DBL011` | Config-level path exclusion                        |
| `DBL012` | Malformed suppression likely broader than intended |
| `DBL013` | Unknown/suspicious suppression comment             |
| `DBL014` | Suppression in non-generated production code       |
| `DBL015` | Vulnerability/dependency audit suppression         |

Example output:

```text
HIGH DBL001 src/api.py:91 mypy blanket ignore
  `# type: ignore` suppresses all type checker errors on this line.
  Prefer `# type: ignore[specific-code]` with a reason.
```

---

# Suggested review prompts

For each tool:

## Ruff/Flake8/Pylint

* Can the code be changed to satisfy the rule?
* Is the rule still enabled?
* Is the ignore too broad?
* Can the ignore be limited to a specific code?
* Is this generated code?

## Mypy/Pyright/Pytype/Ty

* Is the library now typed?
* Would `cast`, `Protocol`, `TypedDict`, or a stub fix this?
* Is the ignored code hiding more than one error?
* Can the ignore be code-specific?

## Bandit/Semgrep/Secrets

* Is the suppressed issue security-relevant?
* Is there a threat model note?
* Is there an issue link or expiry?
* Can the code be made safe instead?

## Pytest/Unittest

* Is the skip still needed?
* Is it unconditional?
* Does it have a reason?
* Does `xfail` use `strict=True`?
* Is there a ticket for removal?

## Coverage

* Is code excluded because it is truly unreachable/platform-specific?
* Is the exclusion hiding untested production logic?
* Is a whole file/path omitted?

---

# Recommended initial MVP

## MVP commands

```bash
dont_be_lazy scan
dont_be_lazy summary
dont_be_lazy list checks
dont_be_lazy config-suppressions
```

## MVP supported tools

1. Ruff / Flake8 `noqa`
2. Mypy / generic `type: ignore`
3. Pyright `pyright: ignore`
4. Pylint `disable` / `enable`
5. Bandit `nosec`
6. Black `fmt: off/on/skip`
7. isort `skip`, `skip_file`, `off/on`
8. coverage.py `pragma: no cover`, `pragma: no branch`
9. pytest `skip`, `skipif`, `xfail`, `pytest.skip`, `pytest.xfail`
10. unittest skips

## MVP output

* Table
* JSON
* Markdown

## MVP parsing

* `tokenize` for comments
* `ast` for pytest/unittest
* `tomllib` + `configparser` + JSON
* optional YAML

---

# Nice-to-have v2

```bash
dont_be_lazy stale
dont_be_lazy owners
dont_be_lazy explain
dont_be_lazy baseline
dont_be_lazy scan --format sarif
```

v2 features:

* Git blame/history.
* Baseline/new-only mode.
* SARIF output.
* Custom pattern registry.
* Expiry-date enforcement.
* CODEOWNERS integration.
* PR diff mode.
* Markdown report generation.
* “Suppression budget” by package/team.

---

# Example report

```markdown
# dont_be_lazy report

Generated: 2026-05-03

## Summary

| Tool | Count | High | Critical | No reason | Stale |
|---|---:|---:|---:|---:|---:|
| ruff | 121 | 12 | 2 | 100 | 44 |
| mypy | 87 | 19 | 3 | 75 | 51 |
| pytest | 31 | 8 | 0 | 5 | 12 |
| bandit | 6 | 2 | 4 | 6 | 4 |

## Highest priority

1. `src/auth/session.py:88` — `# nosec`
2. `src/legacy/api.py:1` — `# ruff: noqa`
3. `tests/test_billing.py:14` — unconditional `@pytest.mark.skip`
4. `pyproject.toml` — `[tool.mypy] ignore_missing_imports = true`
```

---

# Name and tone

`dont_be_lazy` should be opinionated but not obnoxious.

Recommended tagline:

```text
Find the ignores you forgot to come back to.
```

Default CLI language should avoid shaming individuals. The tool can be spicy in name but professional in output.

Good:

```text
HIGH: Blanket security suppression without reason.
```

Bad:

```text
Jane was lazy here.
```

---

# Final design principle

`dont_be_lazy` should not try to prove that a suppression is unnecessary. That would require running the underlying tools. Instead, it should produce a **complete, reviewable inventory** of places where the repo opted out of checks, with enough context and ranking that humans can decide what deserves cleanup.

[1]: https://docs.astral.sh/ruff/linter/?utm_source=chatgpt.com "The Ruff Linter"
[2]: https://docs.astral.sh/ruff/configuration/?utm_source=chatgpt.com "Configuring Ruff"
[3]: https://flake8.pycqa.org/en/latest/user/options.html?utm_source=chatgpt.com "Full Listing of Options and Their Descriptions - Flake8"
[4]: https://pylint.readthedocs.io/en/stable/user_guide/messages/message_control.html?utm_source=chatgpt.com "Messages control - Pylint 4.0.5 documentation - Read the Docs"
[5]: https://typing.python.org/en/latest/spec/directives.html?utm_source=chatgpt.com "Type checker directives — typing documentation"
[6]: https://docs.basedpyright.com/v1.18.3/configuration/comments/?utm_source=chatgpt.com "Comments"
[7]: https://google.github.io/pytype/errors.html?utm_source=chatgpt.com "pytype | A static type analyzer for Python code - Google"
[8]: https://docs.astral.sh/ty/reference/configuration/?utm_source=chatgpt.com "Configuration | ty"
[9]: https://bandit.readthedocs.io/en/latest/config.html?utm_source=chatgpt.com "Configuration — Bandit documentation - Read the Docs"
[10]: https://black.readthedocs.io/en/stable/usage_and_configuration/the_basics.html?utm_source=chatgpt.com "The basics - Black 26.3.1 documentation - Black code formatter"
[11]: https://pycqa.github.io/isort/docs/configuration/options.html?utm_source=chatgpt.com "Configuration options for isort"
[12]: https://coverage.readthedocs.io/en/latest/excluding.html?utm_source=chatgpt.com "Excluding code from coverage.py - Read the Docs"
[13]: https://docs.pytest.org/en/stable/how-to/skipping.html?utm_source=chatgpt.com "How to use skip and xfail to deal with tests that cannot ..."
[14]: https://jsh9.github.io/pydoclint/how_to_ignore.html?utm_source=chatgpt.com "How to ignore certain violations | pydoclint"
[15]: https://pypi.org/project/vulture/?utm_source=chatgpt.com "vulture"
