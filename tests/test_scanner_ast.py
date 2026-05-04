"""Tests for the Python AST scanner (pytest/unittest skip/xfail)."""

import os

from dont_be_lazy.scanners.python_ast import scan_python_ast

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_tests.py")


def _scan(source: str):
    return scan_python_ast("test.py", source)


def test_pytest_skip_unconditional():
    source = "import pytest\n@pytest.mark.skip\ndef test_foo(): pass\n"
    findings = _scan(source)
    assert any(s.kind == "skip-unconditional" for s in findings)


def test_pytest_skip_with_reason():
    source = 'import pytest\n@pytest.mark.skip(reason="broken")\ndef test_foo(): pass\n'
    findings = _scan(source)
    match = next((s for s in findings if s.kind == "skip-with-reason"), None)
    assert match is not None
    assert match.reason == "broken"


def test_pytest_xfail_nonstrict():
    source = "import pytest\n@pytest.mark.xfail\ndef test_foo(): pass\n"
    findings = _scan(source)
    assert any(s.kind == "xfail-nonstrict" for s in findings)


def test_pytest_xfail_strict():
    source = 'import pytest\n@pytest.mark.xfail(strict=True, reason="bug #1")\ndef test_foo(): pass\n'
    findings = _scan(source)
    match = next((s for s in findings if s.kind == "xfail-strict"), None)
    assert match is not None
    assert match.reason == "bug #1"


def test_pytest_imperative_skip():
    source = 'import pytest\ndef test_foo(): pytest.skip("reason")\n'
    findings = _scan(source)
    assert any(s.kind == "skip-call" for s in findings)


def test_unittest_skip():
    source = 'import unittest\nclass T(unittest.TestCase):\n    @unittest.skip("broken")\n    def test_x(self): pass\n'
    findings = _scan(source)
    assert any(s.tool == "unittest" for s in findings)


def test_unittest_skipif():
    source = (
        "import sys, unittest\n"
        "class T(unittest.TestCase):\n"
        '    @unittest.skipIf(sys.platform=="win32","win")\n'
        "    def test_x(self): pass\n"
    )
    findings = _scan(source)
    assert any(s.kind == "skip-conditional" for s in findings)


def test_fixture_file():
    with open(FIXTURE, encoding="utf-8") as f:
        source = f.read()
    findings = scan_python_ast(FIXTURE, source)
    kinds = {s.kind for s in findings}
    assert "skip-unconditional" in kinds
    assert "skip-with-reason" in kinds
    assert "xfail-nonstrict" in kinds
    assert "xfail-strict" in kinds
