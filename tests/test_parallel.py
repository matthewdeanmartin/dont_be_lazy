"""Tests for parallel scanners."""

from __future__ import annotations

from dont_be_lazy.parallel import parallel_scan_configs, parallel_scan_py


def test_parallel_scan_py_matches_single_job(tmp_path) -> None:
    source = tmp_path / "sample.py"
    source.write_text("value = 1  # noqa\nother = 2  # type: ignore[attr-defined]\n", encoding="utf-8")

    single = sorted(s.id for s in parallel_scan_py([str(source)], jobs=1))
    multi = sorted(s.id for s in parallel_scan_py([str(source)], jobs=2))

    assert single == multi


def test_scan_file_success(tmp_path) -> None:
    from dont_be_lazy.parallel import _scan_file
    source = tmp_path / "sample.py"
    source.write_text("# noqa\n", encoding="utf-8")
    res = _scan_file(str(source), "utf-8", True, True, {})
    assert len(res) > 0


def test_scan_file_os_error() -> None:
    from dont_be_lazy.parallel import _scan_file
    assert _scan_file("non-existent.py", "utf-8", True, True, {}) == []


def test_parallel_scan_py_default_jobs(tmp_path) -> None:
    source = tmp_path / "sample.py"
    source.write_text("# noqa\n", encoding="utf-8")
    res = parallel_scan_py([str(source)], jobs=None)
    assert len(res) > 0


def test_parallel_scan_py_exception_in_worker(tmp_path, monkeypatch) -> None:
    from dont_be_lazy import parallel
    source = tmp_path / "sample.py"
    source.write_text("# noqa\n", encoding="utf-8")

    def broken_scan(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(parallel, "_scan_file", broken_scan)
    # Should not raise exception because of contextlib.suppress
    res = parallel_scan_py([str(source), str(source)], jobs=2)
    assert res == []


def test_parallel_scan_configs_default_jobs(tmp_path) -> None:
    config = tmp_path / "pyproject.toml"
    config.write_text("[tool.ruff.lint]\nignore = ['E501']\n", encoding="utf-8")
    res = parallel_scan_configs([str(config)], jobs=None)
    assert len(res) > 0


def test_parallel_scan_configs_exception_in_worker(tmp_path, monkeypatch) -> None:
    from dont_be_lazy import parallel
    config = tmp_path / "pyproject.toml"
    config.write_text("[tool.ruff.lint]\nignore = ['E501']\n", encoding="utf-8")

    def broken_scan(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(parallel, "_scan_config_file", broken_scan)
    res = parallel_scan_configs([str(config), str(config)], jobs=2)
    assert res == []
