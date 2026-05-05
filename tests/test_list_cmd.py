"""Tests for the `list` subcommand and registry."""

import json
import subprocess
import sys

from dont_be_lazy.registry import all_tools, config_entries, entries_for_tool, inline_entries


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", *args],
        capture_output=True,
        check=False,
        text=True,
    )


def test_registry_all_tools():
    tools = all_tools()
    assert "ruff" in tools
    assert "mypy" in tools
    assert "bandit" in tools
    assert "pytest" in tools
    assert "semgrep" in tools
    assert "ty" in tools
    assert "pytype" in tools


def test_registry_entries_for_tool():
    entries = entries_for_tool("pytest")
    kinds = {e.kind for e in entries}
    assert "skip-unconditional" in kinds
    assert "xfail-nonstrict" in kinds
    assert "xfail-strict" in kinds


def test_registry_inline_entries():
    entries = inline_entries("ruff")
    assert all(e.inline for e in entries)
    assert any(e.kind == "noqa-blanket" for e in entries)


def test_registry_config_entries():
    entries = config_entries("ruff")
    assert all(not e.inline for e in entries)
    assert any(e.kind == "config-ignore" for e in entries)


def test_cli_list_tools():
    result = run_cli("list", "tools")
    assert result.returncode == 0
    lines = result.stdout.strip().splitlines()
    assert "ruff" in lines
    assert "semgrep" in lines
    assert "ty" in lines


def test_cli_list_checks_all():
    result = run_cli("list", "checks")
    assert result.returncode == 0
    assert "ruff" in result.stdout
    assert "mypy" in result.stdout
    assert "bandit" in result.stdout


def test_cli_list_checks_tool_filter():
    result = run_cli("list", "checks", "--tool", "pytest")
    assert result.returncode == 0
    assert "pytest" in result.stdout
    assert "ruff" not in result.stdout


def test_cli_list_checks_json():
    result = run_cli("list", "checks", "--format", "json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert all("tool" in e and "kind" in e for e in data)


def test_cli_list_patterns():
    result = run_cli("list", "patterns", "--tool", "coverage")
    assert result.returncode == 0
    assert "coverage" in result.stdout


def test_cli_list_only_inline():
    result = run_cli("list", "checks", "--only-inline")
    assert result.returncode == 0
    # Config-only entries like "omit-broad" should not appear
    assert "omit-broad" not in result.stdout


def test_cli_list_only_config():
    result = run_cli("list", "checks", "--only-config")
    assert result.returncode == 0
    assert "config-ignore" in result.stdout
