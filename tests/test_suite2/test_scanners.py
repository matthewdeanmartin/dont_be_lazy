from dont_be_lazy.models import RiskLevel, ScopeKind
from dont_be_lazy.scanners.python_ast import scan_python_ast
from dont_be_lazy.scanners.python_comments import scan_python_comments


def test_scan_pylint_comments():
    code = """
# pylint: disable=invalid-name
def x():
    pass

# pylint: disable=missing-docstring
# some code
# pylint: enable=missing-docstring

# pylint: disable-next=unused-argument
def y(arg):
    pass
"""
    results = scan_python_comments("test.py", code)

    # We expect 3 suppressions
    assert len(results) == 3

    # 1. disable=invalid-name (line scope)
    assert results[0].tool == "pylint"
    assert results[0].kind == "disable-line"
    assert "invalid-name" in results[0].codes
    assert results[0].line == 2

    # 2. disable=missing-docstring (block scope)
    assert results[1].tool == "pylint"
    assert results[1].kind == "disable-block"
    assert "missing-docstring" in results[1].codes
    assert results[1].line == 6
    assert results[1].end_line == 8

    # 3. disable-next=unused-argument
    assert results[2].tool == "pylint"
    assert results[2].kind == "disable-next"
    assert "unused-argument" in results[2].codes
    assert results[2].line == 10


def test_scan_ruff_noqa():
    code = """
def x():
    y = 1 # noqa
    z = 2 # noqa: F401

# ruff: noqa
"""
    results = scan_python_comments("test.py", code)
    assert len(results) == 3

    # 1. noqa blanket
    assert results[0].tool == "ruff"
    assert results[0].kind == "noqa-blanket"
    assert results[0].risk == RiskLevel.high

    # 2. noqa specific
    assert results[1].tool == "ruff"
    assert results[1].kind == "noqa-specific"
    assert "F401" in results[1].codes

    # 3. ruff: noqa (file)
    assert results[2].tool == "ruff"
    assert results[2].kind == "file-noqa"
    assert results[2].scope == ScopeKind.file


def test_scan_unclosed_block():
    code = """
# pylint: disable=some-check
def x():
    pass
"""
    results = scan_python_comments("test.py", code)
    assert len(results) == 1
    assert "unclosed-block-suppression" in results[0].flags
    assert results[0].risk == RiskLevel.high


def test_scan_pytest_ast():
    code = """
import pytest
import unittest

@pytest.mark.skip(reason="unstable")
def test_one():
    pass

@pytest.mark.skip
def test_two():
    pass

@pytest.mark.xfail(strict=True)
def test_three():
    pass

@unittest.skip("not implemented")
class MyTests(unittest.TestCase):
    def test_four(self):
        pass

def test_five():
    pytest.skip("manual skip")
"""
    results = scan_python_ast("test.py", code)
    # Expected: 5 findings
    assert len(results) == 5

    # 1. pytest.mark.skip(reason="unstable")
    assert results[0].tool == "pytest"
    assert results[0].kind == "skip-with-reason"
    assert results[0].reason == "unstable"

    # 2. pytest.mark.skip
    assert results[1].tool == "pytest"
    assert results[1].kind == "skip-unconditional"
    assert results[1].risk == RiskLevel.high

    # 3. pytest.mark.xfail(strict=True)
    assert results[2].tool == "pytest"
    assert results[2].kind == "xfail-strict"

    # 4. @unittest.skip
    assert results[3].tool == "unittest"
    assert results[3].kind == "skip-unconditional"
    assert results[3].reason == "not implemented"

    # 5. pytest.skip("manual skip")
    assert results[4].tool == "pytest"
    assert results[4].kind == "skip-call"
    assert results[4].reason == "manual skip"


def test_scan_bandit_and_mypy():
    code = """
import os
os.system("ls") # nosec
x: int = "a" # type: ignore[assignment]
# mypy: ignore-errors
"""
    results = scan_python_comments("test.py", code)
    assert len(results) == 3

    assert results[0].tool == "bandit"
    assert results[0].kind == "nosec-blanket"

    assert results[1].tool == "mypy"
    assert results[1].kind == "type-ignore-specific"

    assert results[2].tool == "mypy"
    assert results[2].kind == "file-ignore-errors"
    assert results[2].scope == ScopeKind.file


def test_suspicious_comments():
    code = """
# TODO fix lint later
# Just ignore this check for now
# This is a regular comment
"""
    results = scan_python_comments("test.py", code)
    # We expect 2 suspicious comments
    assert len(results) == 2
    assert results[0].kind == "suspicious-comment"
    assert results[1].kind == "suspicious-comment"
    assert "TODO fix lint" in results[0].text
