"""Explicit unit tests for previously private, now public functions."""

import argparse
import os

from dont_be_lazy.cli import build_global_parser, find_root
from dont_be_lazy.formatters.json_fmt import sup_to_dict
from dont_be_lazy.git import run as git_run
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression
from dont_be_lazy.risk import bump, discount
from dont_be_lazy.walker import gitignored_files


def test_risk_level_helpers():
    assert RiskLevel.idx(RiskLevel.low) == 0
    assert RiskLevel.idx(RiskLevel.critical) == 3
    assert RiskLevel.coerce("high") == RiskLevel.high
    assert RiskLevel.coerce(RiskLevel.medium) == RiskLevel.medium


def test_suppression_methods():
    s = Suppression(
        tool="test",
        kind="test-kind",
        pattern="test-pattern",
        path="path/to/file.py",
        line=10,
        scope=ScopeKind.line,
        codes=[],
        text="some text",
    )
    assert s.normalized_path() == "path/to/file.py"
    assert s.normalized_text() == "some text"
    assert s.nearby_source_hash() is not None
    assert "test-kind" in s.fingerprint_raw()
    assert s.make_id().startswith("DBL")


def test_cli_helpers():
    # find_root
    root = find_root(None)
    assert os.path.isdir(root)

    # build_global_parser
    parser = build_global_parser()
    assert isinstance(parser, argparse.ArgumentParser)
    assert parser.prog == "dont_be_lazy"


def test_risk_bump_discount():
    assert bump(RiskLevel.low) == RiskLevel.medium
    assert bump(RiskLevel.critical) == RiskLevel.critical
    assert discount(RiskLevel.critical) == RiskLevel.high
    assert discount(RiskLevel.low) == RiskLevel.low


def test_json_sup_to_dict():
    s = Suppression(
        tool="test",
        kind="kind",
        pattern="pat",
        path="p.py",
        line=1,
        scope=ScopeKind.line,
        codes=["C1"],
        text="text",
    )
    d = sup_to_dict(s)
    assert d["id"] == s.id
    assert d["tool"] == "test"
    assert d["codes"] == ["C1"]


def test_walker_gitignored_files():
    # This might return None if not in a git repo, but we are in one
    res = gitignored_files(".")
    if res is not None:
        assert isinstance(res, set)


def test_git_run_basic():
    from dont_be_lazy.git import GIT_BIN

    # Simple git command
    res = git_run([GIT_BIN, "rev-parse", "--is-inside-work-tree"], cwd=".")
    assert res is not None
    assert "true" in res.lower()


def test_scanner_ast_helpers():
    import ast

    from dont_be_lazy.scanners.python_ast import get_kwarg
    from dont_be_lazy.scanners.python_ast import make as ast_make
    from dont_be_lazy.scanners.python_ast import static_str

    # static_str
    node = ast.Constant(value="hello")
    assert static_str(node) == "hello"

    # get_kwarg
    kw = ast.keyword(arg="reason", value=ast.Constant(value="because"))
    assert get_kwarg([kw], "reason") == kw.value

    # ast_make
    s = ast_make("tool", "kind", "path.py", 1, "text")
    assert s.tool == "tool"
    assert s.kind == "kind"


def test_scanner_config_helpers():
    from dont_be_lazy.scanners.config import load_optional_module
    from dont_be_lazy.scanners.config import make as cfg_make

    # load_optional_module
    assert load_optional_module("os") is not None
    assert load_optional_module("nonexistent_module_xyz") is None

    # cfg_make
    s = cfg_make("tool", "kind", "path.toml", "key", "val")
    assert s.tool == "tool"
    assert s.kind == "kind"
    assert "val" in s.codes


def test_scanner_comment_helpers():
    from dont_be_lazy.scanners.python_comments import codes
    from dont_be_lazy.scanners.python_comments import make as com_make

    # codes
    assert codes("C1, C2") == ["C1", "C2"]

    # com_make
    s = com_make("tool", "kind", "pat", "path.py", 1, "text")
    assert s.tool == "tool"
    assert s.pattern == "pat"
