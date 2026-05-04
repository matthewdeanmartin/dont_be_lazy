"""Tests for the config-suppressions subcommand."""

import json
import os
import subprocess
import sys

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_config_suppressions_table():
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "--root", FIXTURES, "config-suppressions"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_config_suppressions_json(tmp_path):
    # Create a proper pyproject.toml in a temp root
    (tmp_path / "pyproject.toml").write_bytes(
        b'[tool.ruff.lint]\nignore = ["E501"]\n\n[tool.mypy]\nignore_missing_imports = true\n'
    )
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "--root", str(tmp_path), "config-suppressions", "--format", "json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    doc = json.loads(result.stdout)
    assert "findings" in doc
    tools = {f["tool"] for f in doc["findings"]}
    assert "ruff" in tools or "mypy" in tools


def test_config_suppressions_tool_filter(tmp_path):
    (tmp_path / "pyproject.toml").write_bytes(
        b'[tool.ruff.lint]\nignore = ["E501"]\n\n[tool.mypy]\nignore_missing_imports = true\n'
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "dont_be_lazy",
            "--root",
            str(tmp_path),
            "config-suppressions",
            "--tool",
            "mypy",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    doc = json.loads(result.stdout)
    tools = {f["tool"] for f in doc["findings"]}
    assert tools <= {"mypy"}


def test_config_suppressions_markdown():
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "--root", FIXTURES, "config-suppressions", "--format", "markdown"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "## Summary" in result.stdout


def test_scan_sarif_format():
    result = subprocess.run(
        [sys.executable, "-m", "dont_be_lazy", "scan", FIXTURES, "--format", "sarif", "--no-respect-gitignore"],
        capture_output=True,
        text=True,
    )
    assert result.returncode in (0, 1)
    doc = json.loads(result.stdout)
    assert doc["version"] == "2.1.0"
    assert "runs" in doc
