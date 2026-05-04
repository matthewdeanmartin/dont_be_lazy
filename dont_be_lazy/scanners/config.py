"""Config-file scanner for suppression settings."""

from __future__ import annotations

import configparser
import importlib
import json
import os
from typing import Any, cast

from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression


def _load_optional_module(*names: str) -> Any | None:
    """Import the first available module from *names*."""
    for name in names:
        try:
            return importlib.import_module(name)
        except ModuleNotFoundError:
            continue
    return None


tomllib = _load_optional_module("tomllib", "tomli")
yaml = _load_optional_module("yaml")
_HAS_YAML = yaml is not None


def _make(
    tool: str,
    kind: str,
    path: str,
    key: str,
    value: Any,
    risk: RiskLevel = RiskLevel.medium,
    codes: list[str] | None = None,
    flags: list[str] | None = None,
) -> Suppression:
    return Suppression(
        tool=tool,
        kind=kind,
        pattern=key,
        path=path,
        line=0,
        end_line=None,
        scope=ScopeKind.config,
        codes=codes or (value if isinstance(value, list) else [str(value)]),
        reason=None,
        risk=risk,
        flags=flags or ["config-level"],
        text=f"{key} = {value!r}",
    )


# ---------------------------------------------------------------------------
# TOML-based scanners
# ---------------------------------------------------------------------------


def _scan_ruff_toml(path: str, data: dict[str, Any]) -> list[Suppression]:
    results: list[Suppression] = []
    ruff = data.get("tool", {}).get("ruff", data.get("ruff", {}))
    lint = ruff.get("lint", {})

    if lint.get("ignore"):
        results.append(
            _make(
                "ruff",
                "config-ignore",
                path,
                "lint.ignore",
                lint["ignore"],
                risk=RiskLevel.medium,
                codes=lint["ignore"],
            )
        )
    if lint.get("extend-ignore"):
        results.append(
            _make(
                "ruff",
                "config-ignore",
                path,
                "lint.extend-ignore",
                lint["extend-ignore"],
                risk=RiskLevel.medium,
                codes=lint["extend-ignore"],
            )
        )
    pfi = lint.get("per-file-ignores", {})
    for pattern, ignored in pfi.items():
        codes = ignored if isinstance(ignored, list) else [ignored]
        results.append(
            _make(
                "ruff",
                "per-file-ignores",
                path,
                f"per-file-ignores[{pattern}]",
                codes,
                risk=RiskLevel.medium,
                codes=codes,
            )
        )
    if ruff.get("exclude"):
        results.append(
            _make("ruff", "config-exclude", path, "exclude", ruff["exclude"], risk=RiskLevel.medium, codes=[])
        )
    if ruff.get("extend-exclude"):
        results.append(
            _make(
                "ruff",
                "config-exclude",
                path,
                "extend-exclude",
                ruff["extend-exclude"],
                risk=RiskLevel.medium,
                codes=[],
            )
        )
    return results


def _scan_mypy_toml(path: str, data: dict[str, Any]) -> list[Suppression]:
    results: list[Suppression] = []
    mypy = data.get("tool", {}).get("mypy", {})

    if mypy.get("ignore_missing_imports"):
        results.append(
            _make("mypy", "ignore-missing-imports", path, "ignore_missing_imports", True, risk=RiskLevel.medium)
        )
    if mypy.get("disable_error_code"):
        codes = mypy["disable_error_code"]
        if isinstance(codes, str):
            codes = [codes]
        results.append(
            _make("mypy", "config-disable-code", path, "disable_error_code", codes, risk=RiskLevel.medium, codes=codes)
        )
    if mypy.get("exclude"):
        results.append(
            _make("mypy", "config-exclude", path, "exclude", mypy["exclude"], risk=RiskLevel.medium, codes=[])
        )

    for override in mypy.get("overrides", []):
        if override.get("ignore_errors"):
            modules = override.get("module", [])
            if isinstance(modules, str):
                modules = [modules]
            results.append(
                _make(
                    "mypy",
                    "ignore-errors-config",
                    path,
                    f"overrides[{','.join(modules)}].ignore_errors",
                    True,
                    risk=RiskLevel.critical,
                    codes=modules,
                )
            )
        if override.get("ignore_missing_imports"):
            modules = override.get("module", [])
            if isinstance(modules, str):
                modules = [modules]
            results.append(
                _make(
                    "mypy",
                    "ignore-missing-imports",
                    path,
                    f"overrides[{','.join(modules)}].ignore_missing_imports",
                    True,
                    risk=RiskLevel.medium,
                    codes=modules,
                )
            )
    return results


def _scan_pytest_toml(path: str, data: dict[str, Any]) -> list[Suppression]:
    results: list[Suppression] = []
    opts = data.get("tool", {}).get("pytest", {}).get("ini_options", {})
    addopts = opts.get("addopts", "")
    if isinstance(addopts, list):
        addopts = " ".join(addopts)
    if "-m" in addopts and "not" in addopts:
        results.append(
            _make(
                "pytest",
                "addopts-marker",
                path,
                "addopts",
                addopts,
                risk=RiskLevel.high,
                codes=[],
                flags=["config-level", "marker-exclusion"],
            )
        )
    return results


def _scan_coverage_toml(path: str, data: dict[str, Any]) -> list[Suppression]:
    results: list[Suppression] = []
    cov = data.get("tool", {}).get("coverage", {})
    run = cov.get("run", {})
    report = cov.get("report", {})

    omit = run.get("omit", [])
    if omit:
        src_omit = [p for p in omit if not p.startswith("test")]
        risk = RiskLevel.critical if src_omit else RiskLevel.medium
        results.append(_make("coverage", "omit-broad", path, "run.omit", omit, risk=risk, codes=[]))
    excl = report.get("exclude_lines", []) + report.get("exclude_also", [])
    if excl:
        results.append(
            _make("coverage", "exclude-lines-broad", path, "report.exclude_lines", excl, risk=RiskLevel.high, codes=[])
        )
    return results


def _scan_bandit_toml(path: str, data: dict[str, Any]) -> list[Suppression]:
    results: list[Suppression] = []
    bandit = data.get("tool", {}).get("bandit", {})
    skips = bandit.get("skips", [])
    if skips:
        results.append(_make("bandit", "config-skip", path, "skips", skips, risk=RiskLevel.high, codes=skips))
    excl = bandit.get("exclude_dirs", [])
    if excl:
        results.append(_make("bandit", "config-exclude", path, "exclude_dirs", excl, risk=RiskLevel.medium, codes=[]))
    return results


def _scan_vulture_toml(path: str, data: dict[str, Any]) -> list[Suppression]:
    results: list[Suppression] = []
    vulture = data.get("tool", {}).get("vulture", {})
    if vulture.get("exclude"):
        results.append(
            _make("vulture", "config-exclude", path, "exclude", vulture["exclude"], risk=RiskLevel.medium, codes=[])
        )
    ignore_names = vulture.get("ignore_names", [])
    if ignore_names:
        risk = RiskLevel.critical if any("*" in n for n in ignore_names) else RiskLevel.medium
        results.append(
            _make("vulture", "ignore-names", path, "ignore_names", ignore_names, risk=risk, codes=ignore_names)
        )
    ignore_decs = vulture.get("ignore_decorators", [])
    if ignore_decs:
        results.append(
            _make(
                "vulture",
                "ignore-decorators",
                path,
                "ignore_decorators",
                ignore_decs,
                risk=RiskLevel.medium,
                codes=ignore_decs,
            )
        )
    return results


def _scan_pip_audit_toml(path: str, data: dict[str, Any]) -> list[Suppression]:
    results: list[Suppression] = []
    pip_audit = data.get("tool", {}).get("pip-audit", {})
    ignore_vulns = pip_audit.get("ignore-vulns", [])
    if isinstance(ignore_vulns, str):
        ignore_vulns = [ignore_vulns]
    for vuln in ignore_vulns:
        results.append(
            _make(
                "pip-audit",
                "ignored-vulnerability",
                path,
                "ignore-vulns",
                vuln,
                risk=RiskLevel.critical,
                codes=[vuln],
                flags=["security"],
            )
        )
    return results


def _scan_pydocstyle_toml(path: str, data: dict[str, Any]) -> list[Suppression]:
    results: list[Suppression] = []
    for tool_key in ("pydocstyle", "pydoclint"):
        section = data.get("tool", {}).get(tool_key, {})
        ignore = section.get("ignore", [])
        if isinstance(ignore, str):
            ignore = [ignore]
        if ignore:
            results.append(
                _make(
                    tool_key,
                    "config-ignore",
                    path,
                    f"[tool.{tool_key}].ignore",
                    ignore,
                    risk=RiskLevel.medium,
                    codes=ignore,
                )
            )
    return results


def _scan_isort_toml(path: str, data: dict[str, Any]) -> list[Suppression]:
    results: list[Suppression] = []
    isort = data.get("tool", {}).get("isort", {})
    if isort.get("honor_noqa"):
        results.append(_make("isort", "honor-noqa", path, "honor_noqa", True, risk=RiskLevel.medium, codes=[]))
    skip = isort.get("skip", [])
    if skip:
        results.append(_make("isort", "config-skip", path, "skip", skip, risk=RiskLevel.medium, codes=[]))
    skip_glob = isort.get("skip_glob", [])
    if skip_glob:
        results.append(
            _make("isort", "config-skip-glob", path, "skip_glob", skip_glob, risk=RiskLevel.medium, codes=[])
        )
    return results


def scan_toml(path: str) -> list[Suppression]:
    """Scan a TOML config file for suppression settings."""
    if tomllib is None:
        return []
    try:
        with open(path, "rb") as f:
            data = cast(dict[str, Any], tomllib.load(f))
    except (OSError, ValueError, TypeError):
        return []

    results: list[Suppression] = []
    results.extend(_scan_ruff_toml(path, data))
    results.extend(_scan_mypy_toml(path, data))
    results.extend(_scan_pytest_toml(path, data))
    results.extend(_scan_coverage_toml(path, data))
    results.extend(_scan_bandit_toml(path, data))
    results.extend(_scan_vulture_toml(path, data))
    results.extend(_scan_pip_audit_toml(path, data))
    results.extend(_scan_pydocstyle_toml(path, data))
    results.extend(_scan_isort_toml(path, data))
    return results


# ---------------------------------------------------------------------------
# INI/CFG-based scanners
# ---------------------------------------------------------------------------


def _read_ini(path: str) -> configparser.RawConfigParser:
    cp = configparser.RawConfigParser()
    try:
        cp.read(path, encoding="utf-8")
    except configparser.Error:
        pass
    return cp


def scan_flake8_ini(path: str) -> list[Suppression]:
    """Scan a Flake8-style INI file for suppression settings."""
    cp = _read_ini(path)
    results: list[Suppression] = []
    for section in ("flake8",):
        if not cp.has_section(section):
            continue
        for key in ("ignore", "extend-ignore"):
            if cp.has_option(section, key):
                val = cp.get(section, key)
                codes = [c.strip() for c in val.replace(",", "\n").splitlines() if c.strip()]
                results.append(
                    _make(
                        "flake8", "config-ignore", path, f"[{section}].{key}", codes, risk=RiskLevel.medium, codes=codes
                    )
                )
        if cp.has_option(section, "per-file-ignores"):
            val = cp.get(section, "per-file-ignores")
            results.append(
                _make(
                    "flake8",
                    "per-file-ignores",
                    path,
                    f"[{section}].per-file-ignores",
                    val,
                    risk=RiskLevel.medium,
                    codes=[],
                )
            )
        if cp.has_option(section, "exclude"):
            val = cp.get(section, "exclude")
            results.append(
                _make("flake8", "config-exclude", path, f"[{section}].exclude", val, risk=RiskLevel.medium, codes=[])
            )
    return results


def scan_pylint_ini(path: str) -> list[Suppression]:
    """Scan a pylint INI/RC file for disabled checks."""
    cp = _read_ini(path)
    results: list[Suppression] = []
    for section in ("MESSAGES CONTROL", "messages_control", "pylint.messages_control"):
        if not cp.has_section(section):
            continue
        if cp.has_option(section, "disable"):
            val = cp.get(section, "disable")
            codes = [c.strip() for c in val.replace(",", "\n").splitlines() if c.strip()]
            risk = RiskLevel.critical if "all" in codes else RiskLevel.high
            results.append(
                _make("pylint", "config-disable", path, f"[{section}].disable", codes, risk=risk, codes=codes)
            )
    return results


def scan_mypy_ini(path: str) -> list[Suppression]:
    """Scan a mypy INI file for broad ignore settings."""
    cp = _read_ini(path)
    results: list[Suppression] = []
    if cp.has_section("mypy"):
        if cp.has_option("mypy", "ignore_missing_imports"):
            val = cp.get("mypy", "ignore_missing_imports")
            if val.lower() in ("true", "1", "yes"):
                results.append(
                    _make(
                        "mypy",
                        "ignore-missing-imports",
                        path,
                        "[mypy].ignore_missing_imports",
                        True,
                        risk=RiskLevel.medium,
                    )
                )
        if cp.has_option("mypy", "disable_error_code"):
            val = cp.get("mypy", "disable_error_code")
            codes = [c.strip() for c in val.split(",") if c.strip()]
            results.append(
                _make(
                    "mypy",
                    "config-disable-code",
                    path,
                    "[mypy].disable_error_code",
                    codes,
                    risk=RiskLevel.medium,
                    codes=codes,
                )
            )

    for section in cp.sections():
        if section.startswith("mypy-") and section != "mypy" and cp.has_option(section, "ignore_errors"):
            val = cp.get(section, "ignore_errors")
            if val.lower() in ("true", "1", "yes"):
                results.append(
                    _make(
                        "mypy",
                        "ignore-errors-config",
                        path,
                        f"[{section}].ignore_errors",
                        True,
                        risk=RiskLevel.critical,
                        codes=[section[5:]],
                    )
                )
    return results


def scan_coveragerc(path: str) -> list[Suppression]:
    """Scan a coverage configuration file for omit/exclude directives."""
    cp = _read_ini(path)
    results: list[Suppression] = []
    if cp.has_section("run") and cp.has_option("run", "omit"):
        val = cp.get("run", "omit")
        lines = [entry.strip() for entry in val.splitlines() if entry.strip()]
        results.append(
            _make(
                "coverage",
                "omit-broad",
                path,
                "[run].omit",
                lines,
                risk=RiskLevel.critical if lines else RiskLevel.medium,
                codes=[],
            )
        )
    if cp.has_section("report") and cp.has_option("report", "exclude_lines"):
        val = cp.get("report", "exclude_lines")
        lines = [entry.strip() for entry in val.splitlines() if entry.strip()]
        results.append(
            _make(
                "coverage", "exclude-lines-broad", path, "[report].exclude_lines", lines, risk=RiskLevel.high, codes=[]
            )
        )
    return results


# ---------------------------------------------------------------------------
# JSON-based scanners
# ---------------------------------------------------------------------------


def scan_pyrightconfig(path: str) -> list[Suppression]:
    """Scan pyrightconfig.json for disabled or excluded diagnostics."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []

    results: list[Suppression] = []
    if data.get("typeCheckingMode") == "off":
        results.append(
            _make("pyright", "type-checking-off", path, "typeCheckingMode", "off", risk=RiskLevel.critical, codes=[])
        )
    for key in ("exclude", "ignore"):
        if data.get(key):
            results.append(_make("pyright", "config-exclude", path, key, data[key], risk=RiskLevel.medium, codes=[]))
    # Diagnostics set to "none"
    for k, v in data.items():
        if isinstance(v, str) and v == "none" and k.startswith("report"):
            results.append(_make("pyright", "diagnostic-none", path, k, "none", risk=RiskLevel.medium, codes=[k]))
    return results


# ---------------------------------------------------------------------------
# YAML-based scanners
# ---------------------------------------------------------------------------


def scan_pytype_cfg(path: str) -> list[Suppression]:
    """Scan pytype.cfg for disabled diagnostics and excludes."""
    cp = _read_ini(path)
    results: list[Suppression] = []
    if cp.has_section("pytype"):
        if cp.has_option("pytype", "disable"):
            val = cp.get("pytype", "disable")
            codes = [c.strip() for c in val.split(",") if c.strip()]
            results.append(
                _make("pytype", "config-disable", path, "[pytype].disable", codes, risk=RiskLevel.medium, codes=codes)
            )
        if cp.has_option("pytype", "exclude"):
            val = cp.get("pytype", "exclude")
            results.append(
                _make("pytype", "config-exclude", path, "[pytype].exclude", val, risk=RiskLevel.medium, codes=[])
            )
    return results


def scan_safety_yaml(path: str) -> list[Suppression]:
    """Scan Safety YAML policy files for ignored vulnerability entries."""
    if not _HAS_YAML:
        return []
    assert yaml is not None
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except OSError:
        return []
    except yaml.YAMLError:
        return []

    if not isinstance(data, dict):
        return []
    results: list[Suppression] = []
    ignore_section = data.get("ignore", {})
    if isinstance(ignore_section, dict):
        for vuln_id, details in ignore_section.items():
            has_expiry = isinstance(details, dict) and details.get("expires")
            risk = RiskLevel.high if has_expiry else RiskLevel.critical
            results.append(
                _make(
                    "safety",
                    "ignored-vulnerability",
                    path,
                    f"ignore.{vuln_id}",
                    str(vuln_id),
                    risk=risk,
                    codes=[str(vuln_id)],
                    flags=["security"],
                )
            )
    elif isinstance(ignore_section, list):
        for vuln_id in ignore_section:
            results.append(
                _make(
                    "safety",
                    "ignored-vulnerability",
                    path,
                    f"ignore.{vuln_id}",
                    str(vuln_id),
                    risk=RiskLevel.critical,
                    codes=[str(vuln_id)],
                    flags=["security"],
                )
            )
    return results


def scan_bandit_yaml(path: str) -> list[Suppression]:
    """Scan Bandit YAML config files for skips and excludes."""
    if not _HAS_YAML:
        return []
    assert yaml is not None
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except OSError:
        return []
    except yaml.YAMLError:
        return []

    if not isinstance(data, dict):
        return []
    results: list[Suppression] = []
    skips = data.get("skips", [])
    if skips:
        results.append(
            _make("bandit", "config-skip", path, "skips", skips, risk=RiskLevel.high, codes=[str(s) for s in skips])
        )
    excl = data.get("exclude_dirs", [])
    if excl:
        results.append(_make("bandit", "config-exclude", path, "exclude_dirs", excl, risk=RiskLevel.medium, codes=[]))
    return results


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_CONFIG_FILENAMES = {
    "pyproject.toml": scan_toml,
    "ruff.toml": scan_toml,
    ".ruff.toml": scan_toml,
    ".flake8": scan_flake8_ini,
    "setup.cfg": scan_flake8_ini,
    "tox.ini": scan_flake8_ini,
    ".pylintrc": scan_pylint_ini,
    "mypy.ini": scan_mypy_ini,
    ".mypy.ini": scan_mypy_ini,
    "pytest.ini": lambda p: [],  # handled via pyproject.toml section
    ".coveragerc": scan_coveragerc,
    "pyrightconfig.json": scan_pyrightconfig,
    "bandit.yaml": scan_bandit_yaml,
    ".bandit": scan_bandit_yaml,
    "pytype.cfg": scan_pytype_cfg,
    ".safety-policy.yml": scan_safety_yaml,
    "safety-policy.yml": scan_safety_yaml,
}


def scan_config_file(path: str) -> list[Suppression]:
    """Dispatch to the appropriate config scanner based on filename."""
    name = os.path.basename(path)
    scanner = _CONFIG_FILENAMES.get(name)
    if scanner:
        return scanner(path)
    return []


_VULTURE_WHITELIST_NAMES = {"vulture_whitelist.py", "whitelist.py", "dead_code_whitelist.py"}


def scan_vulture_whitelist(path: str) -> list[Suppression]:
    """Flag a likely vulture whitelist file as a broad dead-code suppression."""
    return [
        _make(
            "vulture",
            "whitelist-file",
            path,
            os.path.basename(path),
            path,
            risk=RiskLevel.high,
            codes=[],
            flags=["file-wide"],
        )
    ]


def find_and_scan_configs(root: str) -> list[Suppression]:
    """Locate known config files under root and scan them."""
    results: list[Suppression] = []
    for name in _CONFIG_FILENAMES:
        path = os.path.join(root, name)
        if os.path.isfile(path):
            results.extend(scan_config_file(path))

    # Vulture whitelist files anywhere under root
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fn in _VULTURE_WHITELIST_NAMES:
                results.extend(scan_vulture_whitelist(os.path.join(dirpath, fn)))

    return results
