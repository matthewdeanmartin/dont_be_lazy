"""Sample test file with skip/xfail patterns."""

import sys
import unittest

import pytest


@pytest.mark.skip
def test_unconditional_skip():
    pass


@pytest.mark.skip(reason="broken on CI")
def test_skip_with_reason():
    pass


@pytest.mark.skipif(sys.platform == "win32", reason="windows only")
def test_skipif():
    pass


@pytest.mark.xfail
def test_xfail_no_strict():
    pass


@pytest.mark.xfail(strict=True, reason="bug #123")
def test_xfail_strict():
    pass


def test_imperative_skip():
    pytest.skip("not needed here")


def test_imperative_xfail():
    pytest.xfail("known failure")


class MyTests(unittest.TestCase):
    @unittest.skip("broken")
    def test_skip(self):
        pass

    @unittest.skipIf(sys.platform == "win32", "not windows")
    def test_skip_if(self):
        pass

    def test_skip_test(self):
        self.skipTest("skip this one")
