# `dont_be_lazy` Implementation Plan

See [spec.md](spec.md) for the full specification.

---

## Phase 1 — Core engine and MVP scan

Goal: `dont_be_lazy scan` and `dont_be_lazy summary` work end-to-end on a real Python repo.

### 1.1 Data model (`dont_be_lazy/models.py`)

Define the core `Suppression` dataclass (see spec §Core model):

- Fields: `id`, `tool`, `kind`, `pattern`, `path`, `line`, `end_line`, `scope`, `codes`, `reason`, `risk`, `flags`, `text`
- `RiskLevel` enum: `low`, `medium`, `high`, `critical`
- `ScopeKind` enum: `line`, `next-line`, `block`, `file`, `module`, `config`, `path`, `test`, `unknown`
- Helper: `fingerprint()` — stable hash of `(path, kind, codes, nearby source hash)` for baseline use later

### 1.2 File walker (`dont_be_lazy/walker.py`)

Walk a directory tree and yield paths to scan:

- Respect `.gitignore` via subprocess `git ls-files` fallback or line-by-line gitignore parser (no heavy dep)
- Skip default dirs: `.git/`, `.venv/`, `venv/`, `__pycache__/`, `dist/`, `build/`, `.mypy_cache/`, `.ruff_cache/`, `.pytest_cache/`
- Default file extensions: `.py`, `.pyi`, `.toml`, `.ini`, `.cfg`, `.yaml`, `.yml`, `.json`
- Honour `--include`/`--exclude` globs

### 1.3 Python comment scanner (`dont_be_lazy/scanners/python_comments.py`)

Use `tokenize` (stdlib) to extract real comments (not string contents):

Tools to detect (MVP list from spec §MVP supported tools):

| Tool | Patterns |
|---|---|
| Ruff/Flake8 | `# noqa`, `# noqa: F401`, `# ruff: noqa`, `# flake8: noqa` |
| Mypy | `# type: ignore`, `# type: ignore[code]`, `# mypy: ignore-errors` |
| Pyright | `# pyright: ignore`, `# pyright: ignore[code]` |
| Pylint | `# pylint: disable=...`, `# pylint: enable=...`, `# pylint: disable-next=...` |
| Bandit | `# nosec`, `# nosec B602` |
| Black | `# fmt: skip`, `# fmt: off`, `# fmt: on` |
| isort | `# isort: skip`, `# isort: skip_file`, `# isort: off`, `# isort: on` |
| coverage | `# pragma: no cover`, `# pragma: no branch` |

Risk scoring per spec §Risk scoring.

Block tracking: pair `off`/`disable` with matching `on`/`enable`; if unmatched, set `flags=["unclosed-block-suppression"]` and `risk=high`.

### 1.4 Python AST scanner (`dont_be_lazy/scanners/python_ast.py`)

Parse source with `ast` to find pytest/unittest decorators and calls:

- `@pytest.mark.skip`, `@pytest.mark.skipif`, `@pytest.mark.xfail`
- `pytest.skip(...)`, `pytest.xfail(...)`
- `@unittest.skip`, `@unittest.skipIf`, `@unittest.skipUnless`
- `raise unittest.SkipTest`, `self.skipTest`
- Extract static `reason=` strings; flag dynamic reasons

### 1.5 Config scanner (`dont_be_lazy/scanners/config.py`)

Parse project config files (no tool execution):

- `pyproject.toml` via `tomllib` (3.11+) or `tomli` optional dep; fall back to regex for older Python
- `.flake8`, `setup.cfg`, `tox.ini` via `configparser`
- `mypy.ini`, `pytest.ini`, `.coveragerc` via `configparser`
- `pyrightconfig.json` via `json`
- `bandit.yaml`, `.bandit` via PyYAML if available, else regex fallback

Keys to detect per spec §Supported suppressions and checks (config subsections for each tool).

### 1.6 Risk scorer (`dont_be_lazy/risk.py`)

Implement the additive risk formula from spec §Risk scoring.
Accept a `Suppression` and return a `RiskLevel`. Applied after scanning.

### 1.7 Reason extractor (`dont_be_lazy/reason.py`)

Extract reason from trailing comments, `reason=` kwargs, and recognize quality levels: `none`, `placeholder`, `plain-text`, `issue-link`, `expiry`.
Detect expiry formats from spec §Reason extraction.

### 1.8 Output formatters (`dont_be_lazy/formatters/`)

- `table.py` — rich/plain-text columnar output (use stdlib `textwrap`; no rich dep required for MVP)
- `json_fmt.py` — JSON schema from spec §JSON output
- `markdown_fmt.py` — Markdown table

### 1.9 CLI wiring (`dont_be_lazy/cli.py`)

Replace stub with full `argparse` tree:

- Global options: `--root`, `--config`, `--include`, `--exclude`, `--respect-gitignore`, `--no-color`, `-v`, `-q`, `--version`
- Subcommand `scan` with options from spec §scan
- Subcommand `summary` with options from spec §summary
- Exit codes per spec §Exit codes

### 1.10 Config loader (`dont_be_lazy/config_loader.py`)

Discovery order from spec §Config file:
1. `--config` explicit
2. `pyproject.toml [tool.dont_be_lazy]`
3. `dont_be_lazy.toml`
4. `.dont-be-lazy.toml`
5. Built-in defaults

### Phase 1 tests

- `tests/test_models.py` — Suppression fields, fingerprint stability
- `tests/test_walker.py` — Path filtering, extension filtering
- `tests/test_scanner_comments.py` — Token-level detection; golden fixtures that confirm strings/docstrings are NOT flagged
- `tests/test_scanner_ast.py` — pytest/unittest detection; reason extraction
- `tests/test_scanner_config.py` — pyproject.toml, .flake8, mypy.ini parsing
- `tests/test_risk.py` — Risk scoring for representative suppressions
- `tests/test_formatters.py` — Table, JSON, Markdown output shape
- `tests/test_cli.py` — Smoke test `scan` and `summary` against `tests/fixtures/`
- `tests/fixtures/` — Small sample `.py` and config files covering each tool

### Phase 1 deliverables

```
dont_be_lazy/
    models.py
    walker.py
    risk.py
    reason.py
    config_loader.py
    cli.py              (replaced)
    scanners/
        __init__.py
        python_comments.py
        python_ast.py
        config.py
    formatters/
        __init__.py
        table.py
        json_fmt.py
        markdown_fmt.py
tests/
    fixtures/           (sample files)
    test_models.py
    test_walker.py
    test_scanner_comments.py
    test_scanner_ast.py
    test_scanner_config.py
    test_risk.py
    test_formatters.py
    test_cli.py         (extended)
```

---

## Phase 2 — Full scan coverage + `list` + `config-suppressions`

Goal: Complete tool coverage per spec, add `list checks` and `config-suppressions` subcommands.

### 2.1 Extend Python comment scanner

Add remaining tools from spec:

- Pytype: `# pytype: disable=...`, `# pytype: enable=...`
- Astral `ty`: `# ty: ignore`, `# ty: ignore[rule]`
- Semgrep: `# nosemgrep`, `# nosemgrep: rule`
- Detect-secrets: `# pragma: allowlist secret`, `# pragma: whitelist secret`
- autopep8/yapf: `# autopep8: off/on`, `# yapf: disable/enable`
- Ruff range: `# ruff: disable[...]`, `# ruff: enable[...]`, `# ruff: file-ignore[...]`
- Unknown/suspicious: catch `ignore this`, `disable check`, `TODO fix lint`, etc. (spec §General source comments)

### 2.2 Extend config scanner

Add remaining config files and keys:

- `ruff.toml`, `.ruff.toml`
- `.pylintrc` (INI)
- `pyrightconfig.json` — `typeCheckingMode`, `exclude`, `ignore`, per-diagnostic `none`
- `bandit.yaml` / `.bandit`
- `pytype.cfg`
- Safety `.safety-policy.yml` / `safety-policy.yml`
- pip-audit config in `pyproject.toml`
- Vulture `pyproject.toml` + whitelist files
- pydocstyle/pydoclint `pyproject.toml`
- isort `honor_noqa`, `skip`, `skip_glob`

### 2.3 Hypothesis scanner

Extend AST scanner:

- `@settings(suppress_health_check=[...])`
- `@settings(deadline=None)`

### 2.4 `list` subcommand (`dont_be_lazy/commands/list_cmd.py`)

```
dont_be_lazy list tools
dont_be_lazy list checks
dont_be_lazy list checks --tool mypy
dont_be_lazy list patterns --tool pytest
```

Driven by a registry (`dont_be_lazy/registry.py`) that declares every known tool, its patterns, scope, and risk defaults. Scanners register themselves into this registry.

### 2.5 `config-suppressions` subcommand (`dont_be_lazy/commands/config_suppression_cmd.py`)

Runs only the config scanner on discovered config files; formats output per spec §config-suppressions.

### 2.6 Custom pattern support (`dont_be_lazy/custom_patterns.py`)

Load from `[tool.dont_be_lazy.custom_patterns]` in config. Compile regexes once; support named groups `token`, `codes`, `reason`, `scope`, `tool`. Apply alongside built-in scanners.

### 2.7 Policy engine (`dont_be_lazy/policy.py`)

Implement rule IDs DBL001–DBL015 from spec §Policy checks.
Load `[tool.dont_be_lazy.policy]` and per-tool overrides.

### 2.8 SARIF formatter (`dont_be_lazy/formatters/sarif.py`)

Implement SARIF 2.1.0 output; gated behind `pip install dont_be_lazy[sarif]` or included if schema is small.

### 2.9 JSONL formatter (`dont_be_lazy/formatters/jsonl_fmt.py`)

One JSON object per line.

### Phase 2 tests

- `tests/test_scanner_extended.py` — pytype, ty, semgrep, secrets, autopep8/yapf
- `tests/test_scanner_config_extended.py` — vulture, pyright JSON, safety YAML, pip-audit
- `tests/test_hypothesis_scanner.py`
- `tests/test_list_cmd.py`
- `tests/test_config_suppression_cmd.py`
- `tests/test_custom_patterns.py`
- `tests/test_policy.py` — each DBL rule fires correctly
- `tests/test_sarif.py` — validates SARIF schema shape

---

## Phase 3 — Advanced subcommands, git integration, baseline

Goal: `stale`, `owners`, `explain`, `baseline`, `rules`, and git-blame/history integration.

### 3.1 Git integration (`dont_be_lazy/git.py`)

- `git blame` per line: author, date
- `git log -S <pattern>` for first-seen estimate
- `git diff <REF>` for `--since` changed-files mode
- Degrade gracefully if not in a git repo or git unavailable

### 3.2 `stale` subcommand (`dont_be_lazy/commands/stale_cmd.py`)

Age strategy from spec §stale:
1. Baseline `first_seen`
2. `--with-git-history` → `git log -S`
3. `--with-git-blame` → blame date
4. Mark unknown

### 3.3 `owners` subcommand (`dont_be_lazy/commands/owners_cmd.py`)

Group suppressions by author/email via `git blame`. Optional `--owner-map` for CODEOWNERS-style mapping.

### 3.4 `explain` subcommand (`dont_be_lazy/commands/explain_cmd.py`)

Accept `path:line` or `DBLxxxxxx` ID. Output tool, why it is a suppression, scope, risk rationale, suggested review prompts (per spec §Suggested review prompts).

### 3.5 `baseline` subcommand (`dont_be_lazy/commands/baseline_cmd.py`)

```
dont_be_lazy baseline create --output .dont-be-lazy-baseline.json
dont_be_lazy baseline check  --baseline .dont-be-lazy-baseline.json
dont_be_lazy baseline prune  --baseline .dont-be-lazy-baseline.json
```

Fingerprint: `(normalized path, kind, codes tuple, nearby-source hash)`.
`new-only` mode: report suppressions absent from baseline.

### 3.6 `rules` subcommand (`dont_be_lazy/commands/rules_cmd.py`)

```
dont_be_lazy rules list
dont_be_lazy rules test
```

Display active policy rules; `rules test` runs policy against current findings and reports which rules would fire.

### 3.7 `scan --since REF` (`dont_be_lazy/diff.py`)

Run `git diff --name-only REF` and restrict scan to changed files. Optionally restrict to changed lines.

### 3.8 Parallel scanning (`dont_be_lazy/parallel.py`)

Use `concurrent.futures.ProcessPoolExecutor` with `--jobs N` (default `os.cpu_count()`). Each worker handles a batch of files and returns a list of `Suppression` objects.

### 3.9 `--stdin` mode

Read file paths from stdin (one per line); scan only those files.

### 3.10 Generated-path risk discount

Apply `risk_discount = true` for paths matching `[tool.dont_be_lazy.generated].paths` globs — lower risk by one level.

### Phase 3 tests

- `tests/test_git.py` — mock subprocess; blame/log/diff parsing
- `tests/test_stale_cmd.py`
- `tests/test_owners_cmd.py`
- `tests/test_explain_cmd.py`
- `tests/test_baseline_cmd.py` — create, check, prune round-trips
- `tests/test_rules_cmd.py`
- `tests/test_diff.py`
- `tests/test_parallel.py` — multiple workers produce same result as single-threaded

---

## Cross-cutting concerns (all phases)

- **False-positive guard**: every scanner must use `tokenize`/`ast`, not bare regex on raw source, to avoid flagging strings and docstrings.
- **Multiple suppressions per line**: one `Suppression` per token; shared `line` number.
- **Encoding**: try UTF-8, fall back to `latin-1`; log decode errors.
- **Zero heavy deps at install time**: YAML via `PyYAML` only if installed; SARIF and YAML gated under extras.
- **Python 3.9 compat**: use `tomllib` shim or require 3.11+; use `Union[X, Y]` not `X | Y`.
- **Unique IDs**: generate `id` as `DBL` + zero-padded hash of fingerprint, stable across runs.
