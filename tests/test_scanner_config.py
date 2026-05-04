"""Tests for the config-file scanner."""

import os

from dont_be_lazy.models import RiskLevel
from dont_be_lazy.scanners.config import scan_coveragerc, scan_flake8_ini, scan_mypy_ini, scan_pyrightconfig, scan_toml

FIXTURE_TOML = os.path.join(os.path.dirname(__file__), "fixtures", "sample_pyproject.toml")


def test_ruff_ignore_from_toml():
    findings = scan_toml(FIXTURE_TOML)
    ruff = [s for s in findings if s.tool == "ruff"]
    assert any(s.kind == "config-ignore" for s in ruff)


def test_mypy_ignore_missing_from_toml():
    findings = scan_toml(FIXTURE_TOML)
    mypy = [s for s in findings if s.tool == "mypy"]
    assert any(s.kind == "ignore-missing-imports" for s in mypy)


def test_mypy_ignore_errors_override():
    findings = scan_toml(FIXTURE_TOML)
    mypy = [s for s in findings if s.tool == "mypy"]
    assert any(s.kind == "ignore-errors-config" for s in mypy)
    match = next(s for s in mypy if s.kind == "ignore-errors-config")
    assert match.risk == RiskLevel.critical


def test_pytest_addopts_from_toml():
    findings = scan_toml(FIXTURE_TOML)
    pytest_f = [s for s in findings if s.tool == "pytest"]
    assert any(s.kind == "addopts-marker" for s in pytest_f)


def test_coverage_omit_from_toml():
    findings = scan_toml(FIXTURE_TOML)
    cov = [s for s in findings if s.tool == "coverage"]
    assert any(s.kind == "omit-broad" for s in cov)


def test_bandit_skips_from_toml():
    findings = scan_toml(FIXTURE_TOML)
    bandit = [s for s in findings if s.tool == "bandit"]
    assert any(s.kind == "config-skip" for s in bandit)
    match = next(s for s in bandit if s.kind == "config-skip")
    assert "B101" in match.codes


def test_flake8_ini(tmp_path):
    ini = tmp_path / ".flake8"
    ini.write_text("[flake8]\nignore = E203,W503\nper-file-ignores =\n    __init__.py:F401\n")
    findings = scan_flake8_ini(str(ini))
    assert any(s.kind == "config-ignore" for s in findings)
    assert any(s.kind == "per-file-ignores" for s in findings)


def test_mypy_ini(tmp_path):
    ini = tmp_path / "mypy.ini"
    ini.write_text("[mypy]\nignore_missing_imports = True\n\n[mypy-legacy.*]\nignore_errors = True\n")
    findings = scan_mypy_ini(str(ini))
    assert any(s.kind == "ignore-missing-imports" for s in findings)
    assert any(s.kind == "ignore-errors-config" for s in findings)


def test_coveragerc(tmp_path):
    rc = tmp_path / ".coveragerc"
    rc.write_text("[run]\nomit =\n    tests/*\n\n[report]\nexclude_lines =\n    pragma: no cover\n")
    findings = scan_coveragerc(str(rc))
    assert any(s.kind == "omit-broad" for s in findings)
    assert any(s.kind == "exclude-lines-broad" for s in findings)


def test_pyrightconfig(tmp_path):
    jf = tmp_path / "pyrightconfig.json"
    jf.write_text('{"typeCheckingMode": "off", "exclude": ["generated"]}')
    findings = scan_pyrightconfig(str(jf))

    match = next((s for s in findings if s.kind == "type-checking-off"), None)
    assert match is not None
    assert match.risk == RiskLevel.critical
