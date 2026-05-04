"""Parallel file scanning using ProcessPoolExecutor."""

from __future__ import annotations

import contextlib
import os
from concurrent.futures import ProcessPoolExecutor, as_completed

from dont_be_lazy.models import Suppression


def _scan_file(
    path: str,
    encoding: str,
    scan_comments: bool,
    scan_ast: bool,
    custom_patterns_cfg: dict[str, object],
) -> list[Suppression]:
    """Worker: scan a single Python file and return Suppression objects."""
    # pylint: disable=import-outside-toplevel
    from dont_be_lazy.custom_patterns import CustomPatternScanner
    from dont_be_lazy.scanners.python_ast import scan_python_ast
    from dont_be_lazy.scanners.python_comments import scan_python_comments

    try:
        with open(path, encoding=encoding, errors="replace") as f:
            source = f.read()
    except OSError:
        return []

    results: list[Suppression] = []
    if scan_comments:
        results.extend(scan_python_comments(path, source))
    if scan_ast:
        results.extend(scan_python_ast(path, source))
    if custom_patterns_cfg:
        scanner = CustomPatternScanner(custom_patterns_cfg)
        results.extend(scanner.scan(path, source))
    return results


def _scan_config_file(path: str) -> list[Suppression]:
    # pylint: disable=import-outside-toplevel
    from dont_be_lazy.scanners.config import scan_config_file

    return scan_config_file(path)


def parallel_scan_py(
    py_paths: list[str],
    encoding: str = "utf-8",
    scan_comments: bool = True,
    scan_ast: bool = True,
    custom_patterns_cfg: dict[str, object] | None = None,
    jobs: int | None = None,
) -> list[Suppression]:
    """Scan Python files in parallel; falls back to sequential on single job."""
    if jobs is None:
        jobs = os.cpu_count() or 1

    results: list[Suppression] = []
    cfg = custom_patterns_cfg or {}

    if jobs <= 1 or len(py_paths) <= 1:
        for p in py_paths:
            results.extend(_scan_file(p, encoding, scan_comments, scan_ast, cfg))
        return results

    with ProcessPoolExecutor(max_workers=jobs) as executor:
        futures = {executor.submit(_scan_file, p, encoding, scan_comments, scan_ast, cfg): p for p in py_paths}
        for fut in as_completed(futures):
            with contextlib.suppress(Exception):
                results.extend(fut.result())
    return results


def parallel_scan_configs(
    config_paths: list[str],
    jobs: int | None = None,
) -> list[Suppression]:
    """Scan config files in parallel."""
    if jobs is None:
        jobs = os.cpu_count() or 1

    results: list[Suppression] = []
    if jobs <= 1 or len(config_paths) <= 1:
        for p in config_paths:
            results.extend(_scan_config_file(p))
        return results

    with ProcessPoolExecutor(max_workers=jobs) as executor:
        futures = {executor.submit(_scan_config_file, p): p for p in config_paths}
        for fut in as_completed(futures):
            with contextlib.suppress(Exception):
                results.extend(fut.result())
    return results
