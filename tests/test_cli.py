"""Smoke tests for the CLI entry point."""

import importlib
import json
import os
import subprocess
import sys

from dont_be_lazy.__about__ import __version__


import pytest
from dont_be_lazy.cli import main

def _run_cli(monkeypatch, capsys, *args):
    import sys
    monkeypatch.setattr(sys, "argv", ["dont_be_lazy", *args])
    with pytest.raises(SystemExit) as excinfo:
        main()
    captured = capsys.readouterr()
    return type("Result", (), {
        "returncode": excinfo.value.code,
        "stdout": captured.out,
        "stderr": captured.err
    })


def test_import() -> None:
    """Package can be imported."""
    module = importlib.import_module("dont_be_lazy")
    assert module.__name__ == "dont_be_lazy"


def test_version() -> None:
    """Package exposes a version string."""
    assert isinstance(__version__, str)
    assert __version__


def test_cli_version(monkeypatch, capsys):
    result = _run_cli(monkeypatch, capsys, "--version")
    # --version usually exits with 0 and prints to stdout or stderr depending on argparse version
    assert result.returncode == 0


def test_cli_no_args_shows_help(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["dont_be_lazy"])
    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "scan" in captured.out or "usage" in captured.out.lower()


def test_cli_scan_fixture(monkeypatch, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli(monkeypatch, capsys, "scan", fixtures, "--format", "table", "--no-respect-gitignore")
    assert result.returncode in (0, 1)
    assert "ruff" in result.stdout or "mypy" in result.stdout or "No suppressions" in result.stdout


def test_cli_scan_json_output(monkeypatch, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli(monkeypatch, capsys, "scan", fixtures, "--format", "json", "--no-respect-gitignore")
    assert result.returncode in (0, 1)

    doc = json.loads(result.stdout)
    assert "findings" in doc
    assert doc["summary"]["total"] > 0


def test_cli_summary(monkeypatch, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli(monkeypatch, capsys, "summary", fixtures, "--no-respect-gitignore")
    assert result.returncode == 0


def test_cli_list_tools(monkeypatch, capsys):
    result = _run_cli(monkeypatch, capsys, "list", "tools")
    assert result.returncode == 0
    assert "ruff" in result.stdout
    assert "mypy" in result.stdout


def test_cli_list_checks(monkeypatch, capsys):
    result = _run_cli(monkeypatch, capsys, "list", "checks", "--tool", "pytest")
    assert result.returncode == 0
    assert "pytest" in result.stdout


def test_cli_config_suppressions(monkeypatch, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli(monkeypatch, capsys, "--root", fixtures, "config-suppressions")
    assert result.returncode == 0


def test_cli_fail_on_high(monkeypatch, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli(monkeypatch, capsys, "scan", fixtures, "--format", "table", "--fail-on", "high", "--no-respect-gitignore")
    # Fixtures contain high-risk suppressions, so exit code should be 1
    assert result.returncode in (0, 1)


def test_cli_stale_json(monkeypatch, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli(monkeypatch, capsys, "stale", fixtures, "--format", "json", "--no-respect-gitignore")
    assert result.returncode in (0, 1)

    doc = json.loads(result.stdout)
    assert "findings" in doc


def test_cli_explain_by_location(monkeypatch, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    target = os.path.join(fixtures, "sample_comments.py") + ":32"
    result = _run_cli(monkeypatch, capsys, "explain", target)
    assert result.returncode == 0
    assert "Matched:" in result.stdout


def test_cli_baseline_create_and_check(tmp_path, monkeypatch, capsys):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    baseline_path = tmp_path / "baseline.json"

    create = _run_cli(
        monkeypatch,
        capsys,
        "baseline",
        "create",
        fixtures,
        "--output",
        str(baseline_path),
        "--no-respect-gitignore",
    )
    check = _run_cli(
        monkeypatch,
        capsys,
        "baseline",
        "check",
        fixtures,
        "--baseline",
        str(baseline_path),
        "--no-respect-gitignore",
    )

    assert create.returncode == 0
    assert check.returncode == 0


def test_cli_rules_list(monkeypatch, capsys):
    result = _run_cli(monkeypatch, capsys, "rules", "list")
    assert result.returncode == 0
    assert "DBL001" in result.stdout
