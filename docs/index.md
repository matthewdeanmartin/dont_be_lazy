# Dont Be Lazy

Dont Be Lazy helps you audit suppression comments and config-level ignores that were supposed to be temporary. It scans repositories for skipped tests, blanket lint ignores, stale type-checker suppressions, security-rule bypasses, formatter exclusions, and similar shortcuts that quietly stick around.

## Start here

- Read the [project overview](overview/README.md) for the problem this tool solves.
- Follow the [installation guide](installation.md) to install the CLI.
- Use the [quick start](usage/quickstart.md) for common commands.
- See [contributing](extending/CONTRIBUTING.md) for local development.

## Core capabilities

- Detect inline suppressions and config-file suppressions across many Python tooling ecosystems.
- Assign risk based on tool, scope, and suppression kind.
- Surface stale suppressions with optional git blame, git history, and baseline support.
- Explain individual findings and evaluate them against built-in policy rules.
- Export findings as table, JSON, JSONL, Markdown, or SARIF where supported.

## Main commands

| Command | Purpose |
|---|---|
| `scan` | Scan files and config for suppressions. |
| `summary` | Group counts by tool, path, scope, owner, age, or risk. |
| `stale` | Focus on older suppressions that need re-review. |
| `owners` | Attribute suppressions to authors or teams. |
| `explain` | Explain one finding in detail. |
| `baseline` | Track accepted suppressions across runs. |
| `rules` | Test findings against built-in DBL policy rules. |

## Release notes

The packaged source changelog lives in the repository root. This docs site includes a short [changelog page](changelog.md) so Read the Docs has a first-class navigation entry.
