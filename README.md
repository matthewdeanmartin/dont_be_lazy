# Dont Be Lazy

Dont Be Lazy scans a repository for lint, type-checking, security, formatting, coverage, and test suppressions that were probably meant to be temporary and then forgotten. It helps teams find blanket ignores, stale skips, config-level exclusions, and other "we'll clean this up later" decisions before they become permanent.

## What it can find

- Inline suppressions such as `# noqa`, `# type: ignore`, `# nosec`, `# nosemgrep`, `# fmt: off`, and skipped tests.
- Config-level suppressions such as ignored rules, per-file ignores, and excluded paths.
- Risky patterns like file-wide ignores, blanket suppressions, non-strict `xfail`, and vulnerability audit ignores.
- Age and ownership signals using git blame, git history, and baseline files.

## Installation

```bash
pipx install dont_be_lazy
```

Or with pip:

```bash
pip install dont_be_lazy
```

For local development:

```bash
git clone https://github.com/matthewdeanmartin/dont_be_lazy.git
cd dont_be_lazy
uv sync --all-extras
```

## Quick usage

Show the CLI:

```bash
dont_be_lazy --help
```

Scan a repository:

```bash
dont_be_lazy scan .
```

Focus on higher-risk suppressions:

```bash
dont_be_lazy scan . --risk high
```

Summarize findings by tool:

```bash
dont_be_lazy summary . --by tool
```

Find stale suppressions with git history:

```bash
dont_be_lazy stale . --older-than 180d --with-git-history
```

Create and check a baseline:

```bash
dont_be_lazy baseline create . --output .dont-be-lazy-baseline.json
dont_be_lazy baseline check . --baseline .dont-be-lazy-baseline.json
```

Review active policy rules:

```bash
dont_be_lazy rules list
dont_be_lazy rules test .
```

Export machine-readable output:

```bash
dont_be_lazy scan . --format sarif --output dont-be-lazy.sarif
```

## Commands

| Command | Purpose |
|---|---|
| `scan` | Find suppressions in code and config files. |
| `summary` | Show grouped counts by tool, kind, scope, owner, age, or risk. |
| `list` | Show supported tools, checks, and known suppression patterns. |
| `config-suppressions` | Scan config-file-level ignores and exclusions. |
| `stale` | Find old suppressions using a time threshold plus optional git metadata. |
| `owners` | Group suppressions by git blame author, email, team, or path. |
| `explain` | Explain one suppression by `path:line` or DBL identifier. |
| `baseline` | Create, check, and prune accepted suppressions over time. |
| `rules` | List policy rules and test current findings against them. |

## Output formats

`scan` supports `table`, `json`, `jsonl`, `markdown`, and `sarif`. Other commands support the subset that fits their output, so it can plug into terminal workflows, CI logs, dashboards, and code-scanning tools.

## Documentation

- [Documentation site](https://dont_be_lazy.readthedocs.io/en/latest/)
- [Project overview](docs/overview/README.md)
- [Installation](docs/installation.md)
- [Quick start](docs/usage/quickstart.md)
- [Contributing](docs/extending/CONTRIBUTING.md)

## License

MIT — see [LICENSE](LICENSE).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
