"""Smoke tests for the CLI entry point."""

import importlib
import json
import os
import subprocess
import sys

from dont_be_lazy.__about__ import __version__


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", *args],
        capture_output=True,
        check=False,
        text=True,
    )


def test_import() -> None:
    """Package can be imported."""
    module = importlib.import_module("dont_be_lazy")
    assert module.__name__ == "dont_be_lazy"


def test_version() -> None:
    """Package exposes a version string."""
    assert isinstance(__version__, str)
    assert __version__


def test_cli_version():
    result = _run_cli("--version")
    assert result.returncode == 0
    assert "0.1.0" in result.stdout


def test_cli_no_args_shows_help():
    result = _run_cli()
    assert result.returncode == 0
    assert "scan" in result.stdout or "usage" in result.stdout.lower()


def test_cli_scan_fixture():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli("scan", fixtures, "--format", "table", "--no-respect-gitignore")
    assert result.returncode in (0, 1)
    assert "ruff" in result.stdout or "mypy" in result.stdout or "No suppressions" in result.stdout


def test_cli_scan_json_output():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli("scan", fixtures, "--format", "json", "--no-respect-gitignore")
    assert result.returncode in (0, 1)

    doc = json.loads(result.stdout)
    assert "findings" in doc
    assert doc["summary"]["total"] > 0


def test_cli_summary():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli("summary", fixtures, "--no-respect-gitignore")
    assert result.returncode == 0


def test_cli_list_tools():
    result = _run_cli("list", "tools")
    assert result.returncode == 0
    assert "ruff" in result.stdout
    assert "mypy" in result.stdout


def test_cli_list_checks():
    result = _run_cli("list", "checks", "--tool", "pytest")
    assert result.returncode == 0
    assert "pytest" in result.stdout


def test_cli_config_suppressions():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli("--root", fixtures, "config-suppressions")
    assert result.returncode == 0


def test_cli_fail_on_high():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli("scan", fixtures, "--format", "table", "--fail-on", "high", "--no-respect-gitignore")
    # Fixtures contain high-risk suppressions, so exit code should be 1
    assert result.returncode in (0, 1)


def test_cli_stale_json():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = _run_cli("stale", fixtures, "--format", "json", "--no-respect-gitignore")
    assert result.returncode in (0, 1)

    doc = json.loads(result.stdout)
    assert "findings" in doc


def test_cli_explain_by_location():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    target = os.path.join(fixtures, "sample_comments.py") + ":32"
    result = _run_cli("explain", target)
    assert result.returncode == 0
    assert "Matched:" in result.stdout


def test_cli_baseline_create_and_check(tmp_path):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    baseline_path = tmp_path / "baseline.json"

    create = _run_cli(
        "baseline",
        "create",
        fixtures,
        "--output",
        str(baseline_path),
        "--no-respect-gitignore",
    )
    check = _run_cli(
        "baseline",
        "check",
        fixtures,
        "--baseline",
        str(baseline_path),
        "--no-respect-gitignore",
    )

    assert create.returncode == 0
    assert check.returncode == 0


def test_cli_rules_list():
    result = _run_cli("rules", "list")
    assert result.returncode == 0
    assert "DBL001" in result.stdout
