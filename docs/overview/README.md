# Overview

Dont Be Lazy is a repository audit tool for finding "temporary" suppressions that tend to become permanent. It looks for inline comments, file-level directives, config-file ignores, skipped tests, and other ways teams silence tools while planning to come back later.

## Why it exists

Teams often add suppressions for practical reasons:

- a lint rule is noisy during a migration
- a type checker lacks enough context
- a security rule needs a documented exception
- a test is flaky and gets skipped "for now"

The problem is not that these exist. The problem is that they are easy to forget. Dont Be Lazy gives you a way to scan for them, sort them by risk, and decide which ones should be removed, narrowed, explained, or accepted into a baseline.

## What it scans

The built-in registry covers many Python-adjacent tools, including:

- linters such as Ruff, Flake8, and Pylint
- type checkers such as mypy, pyright, pytype, and ty
- security and audit tooling such as Bandit, Semgrep, secrets scanning, Safety, and pip-audit
- formatters such as Black, isort, autopep8, and yapf
- coverage and test tooling such as coverage.py, pytest, unittest, and Hypothesis

It detects both inline suppressions and config-level suppressions such as ignored rules, per-file ignores, excluded paths, and skipped checks.

## How to use it

Typical workflows include:

1. Run `dont_be_lazy scan .` to collect findings.
1. Use `dont_be_lazy summary . --by risk` or `--by tool` to see where the problems cluster.
1. Run `dont_be_lazy stale . --older-than 180d --with-git-history` to focus on older suppressions.
1. Use `dont_be_lazy explain PATH:LINE` to review one suppression in detail.
1. Create a baseline when you need to distinguish existing debt from newly introduced suppressions.

## Outputs

The CLI supports human-readable table output and machine-friendly JSON, JSONL, Markdown, and SARIF where appropriate. That makes it useful for local audits, CI checks, pull request reports, and code scanning pipelines.
