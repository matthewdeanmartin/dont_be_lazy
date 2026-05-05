import os

from dont_be_lazy.scanners.python_ast import scan_python_ast
from dont_be_lazy.scanners.python_comments import scan_python_comments
from dont_be_lazy.walker import walk_paths


def test_walk_paths(tmp_path):
    # Create a dummy project
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.py").write_text("print('hello')")
    (root / "b.py").write_text("print('world')")

    subdir = root / "src"
    subdir.mkdir()
    (subdir / "c.py").write_text("print('sub')")

    (root / ".git").mkdir()
    (root / "ignored.txt").write_text("ignore me")

    # Test walking
    paths = list(walk_paths(str(root)))

    # Should find .py files
    py_files = [os.path.basename(p) for p in paths if p.endswith(".py")]
    assert "a.py" in py_files
    assert "b.py" in py_files
    assert "c.py" in py_files
    assert len(py_files) == 3


def test_full_scan_scenario(tmp_path):
    root = tmp_path / "project"
    root.mkdir()

    code_a = """
def x():
    pass # noqa
"""
    (root / "a.py").write_text(code_a)

    code_b = """
import pytest
@pytest.mark.skip
def test_b():
    pass
"""
    (root / "b.py").write_text(code_b)

    # respect_gitignore=False because we didn't init git
    paths = list(walk_paths(str(root), respect_gitignore=False))

    all_findings = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            content = f.read()
        all_findings.extend(scan_python_comments(p, content))
        all_findings.extend(scan_python_ast(p, content))

    assert len(all_findings) == 2
    tools = {f.tool for f in all_findings}
    assert "ruff" in tools
    assert "pytest" in tools


def test_exclude_patterns(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.py").write_text("x=1")
    (root / "b_test.py").write_text("y=2")

    # Walk with exclude
    paths = list(walk_paths(str(root), exclude_globs=["*_test.py"], respect_gitignore=False))
    py_files = [os.path.basename(p) for p in paths if p.endswith(".py")]
    assert "a.py" in py_files
    assert "b_test.py" not in py_files
