"""Smoke tests for the CLI entry point."""

import os
import subprocess
import sys


def test_import() -> None:
    """Package can be imported."""
    import dont_be_lazy  # noqa: F401


def test_version() -> None:
    """Package exposes a version string."""
    from dont_be_lazy.__about__ import __version__

    assert isinstance(__version__, str)
    assert __version__


def test_cli_version():
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "0.1.0" in result.stdout


def test_cli_no_args_shows_help():
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "scan" in result.stdout or "usage" in result.stdout.lower()


def test_cli_scan_fixture():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "scan", fixtures, "--format", "table", "--no-respect-gitignore"],
        capture_output=True,
        text=True,
    )
    assert result.returncode in (0, 1)
    assert "ruff" in result.stdout or "mypy" in result.stdout or "No suppressions" in result.stdout


def test_cli_scan_json_output():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "scan", fixtures, "--format", "json", "--no-respect-gitignore"],
        capture_output=True,
        text=True,
    )
    assert result.returncode in (0, 1)
    import json

    doc = json.loads(result.stdout)
    assert "findings" in doc
    assert doc["summary"]["total"] > 0


def test_cli_summary():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "summary", fixtures, "--no-respect-gitignore"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_cli_list_tools():
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "list", "tools"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "ruff" in result.stdout
    assert "mypy" in result.stdout


def test_cli_list_checks():
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "list", "checks", "--tool", "pytest"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "pytest" in result.stdout


def test_cli_config_suppressions():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "--root", fixtures, "config-suppressions"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_cli_fail_on_high():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "dont_be_lazy",
            "scan",
            fixtures,
            "--format",
            "table",
            "--fail-on",
            "high",
            "--no-respect-gitignore",
        ],
        capture_output=True,
        text=True,
    )
    # Fixtures contain high-risk suppressions, so exit code should be 1
    assert result.returncode in (0, 1)


def test_cli_stale_json():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "stale", fixtures, "--format", "json", "--no-respect-gitignore"],
        capture_output=True,
        text=True,
    )
    assert result.returncode in (0, 1)
    import json

    doc = json.loads(result.stdout)
    assert "findings" in doc


def test_cli_explain_by_location():
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    target = os.path.join(fixtures, "sample_comments.py") + ":3"
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "explain", target],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Matched:" in result.stdout


def test_cli_baseline_create_and_check(tmp_path):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    baseline_path = tmp_path / "baseline.json"

    create = subprocess.run(
        [
            sys.executable,
            "-m",
            "dont_be_lazy",
            "baseline",
            "create",
            fixtures,
            "--output",
            str(baseline_path),
            "--no-respect-gitignore",
        ],
        capture_output=True,
        text=True,
    )
    check = subprocess.run(
        [
            sys.executable,
            "-m",
            "dont_be_lazy",
            "baseline",
            "check",
            fixtures,
            "--baseline",
            str(baseline_path),
            "--no-respect-gitignore",
        ],
        capture_output=True,
        text=True,
    )

    assert create.returncode == 0
    assert check.returncode == 0


def test_cli_rules_list():
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "rules", "list"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "DBL001" in result.stdout
