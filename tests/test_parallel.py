"""Tests for parallel scanners."""

from __future__ import annotations

from dont_be_lazy.parallel import parallel_scan_configs, parallel_scan_py


def test_parallel_scan_py_matches_single_job(tmp_path) -> None:
    source = tmp_path / "sample.py"
    source.write_text("value = 1  # noqa\nother = 2  # type: ignore[attr-defined]\n", encoding="utf-8")

    single = sorted(s.id for s in parallel_scan_py([str(source)], jobs=1))
    multi = sorted(s.id for s in parallel_scan_py([str(source)], jobs=2))

    assert single == multi


def test_parallel_scan_configs_matches_single_job(tmp_path) -> None:
    config = tmp_path / "pyproject.toml"
    config.write_text(
        "[tool.ruff.lint]\nignore = ['E501']\n",
        encoding="utf-8",
    )

    single = sorted(s.id for s in parallel_scan_configs([str(config)], jobs=1))
    multi = sorted(s.id for s in parallel_scan_configs([str(config)], jobs=2))

    assert single == multi
