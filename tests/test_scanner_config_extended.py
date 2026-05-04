"""Tests for extended config scanners (Phase 2)."""

from dont_be_lazy.models import RiskLevel
from dont_be_lazy.scanners.config import (
    find_and_scan_configs,
    scan_pytype_cfg,
    scan_safety_yaml,
    scan_toml,
)


def test_vulture_toml(tmp_path):
    t = tmp_path / "pyproject.toml"
    t.write_bytes(b'[tool.vulture]\nexclude = ["generated"]\nignore_names = ["visit_*"]\n')
    findings = scan_toml(str(t))
    v = [s for s in findings if s.tool == "vulture"]
    assert any(s.kind == "config-exclude" for s in v)
    assert any(s.kind == "ignore-names" for s in v)


def test_vulture_ignore_names_wildcard_critical(tmp_path):
    t = tmp_path / "pyproject.toml"
    t.write_bytes(b'[tool.vulture]\nignore_names = ["*"]\n')
    findings = scan_toml(str(t))

    v = next((s for s in findings if s.tool == "vulture" and s.kind == "ignore-names"), None)
    assert v is not None
    assert v.risk == RiskLevel.critical


def test_pip_audit_toml(tmp_path):
    t = tmp_path / "pyproject.toml"
    t.write_bytes(b'[tool.pip-audit]\nignore-vulns = ["PYSEC-2024-001"]\n')
    findings = scan_toml(str(t))

    p = next((s for s in findings if s.tool == "pip-audit"), None)
    assert p is not None
    assert p.risk == RiskLevel.critical
    assert "PYSEC-2024-001" in p.codes


def test_pydocstyle_toml(tmp_path):
    t = tmp_path / "pyproject.toml"
    t.write_bytes(b'[tool.pydocstyle]\nignore = ["D100", "D104"]\n')
    findings = scan_toml(str(t))
    p = next((s for s in findings if s.tool == "pydocstyle"), None)
    assert p is not None
    assert "D100" in p.codes


def test_isort_honor_noqa_toml(tmp_path):
    t = tmp_path / "pyproject.toml"
    t.write_bytes(b'[tool.isort]\nhonor_noqa = true\nskip = ["generated"]\n')
    findings = scan_toml(str(t))
    i = [s for s in findings if s.tool == "isort"]
    assert any(s.kind == "honor-noqa" for s in i)
    assert any(s.kind == "config-skip" for s in i)


def test_pytype_cfg(tmp_path):
    cfg = tmp_path / "pytype.cfg"
    cfg.write_text("[pytype]\ndisable = attribute-error\nexclude = generated\n")
    findings = scan_pytype_cfg(str(cfg))
    assert any(s.kind == "config-disable" for s in findings)
    assert any(s.kind == "config-exclude" for s in findings)


def test_safety_yaml(tmp_path):
    yml = tmp_path / ".safety-policy.yml"
    yml.write_text("ignore:\n  12345:\n    reason: 'test'\n    expires: '2026-12-01'\n  67890:\n    reason: 'no fix'\n")
    findings = scan_safety_yaml(str(yml))
    assert len(findings) == 2

    with_expiry = next((s for s in findings if "12345" in s.codes), None)
    assert with_expiry is not None
    assert with_expiry.risk == RiskLevel.high  # has expiry

    no_expiry = next((s for s in findings if "67890" in s.codes), None)
    assert no_expiry is not None
    assert no_expiry.risk == RiskLevel.critical  # no expiry


def test_vulture_whitelist_file_detected(tmp_path):
    wl = tmp_path / "vulture_whitelist.py"
    wl.write_text("unused = None\n")
    findings = find_and_scan_configs(str(tmp_path))
    v = next((s for s in findings if s.tool == "vulture" and s.kind == "whitelist-file"), None)
    assert v is not None
