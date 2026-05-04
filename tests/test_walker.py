"""Tests for the file walker."""

import os
import tempfile

from dont_be_lazy.walker import walk_paths


def _make_tree(files: dict) -> str:
    root = tempfile.mkdtemp()
    for rel, content in files.items():
        abs_path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w") as f:
            f.write(content)
    return root


def test_walks_python_files():
    root = _make_tree({"src/a.py": "x=1", "src/b.txt": "nope"})
    paths = list(walk_paths(root, respect_gitignore=False))
    basenames = {os.path.basename(p) for p in paths}
    assert "a.py" in basenames
    assert "b.txt" not in basenames


def test_excludes_venv():
    root = _make_tree({".venv/lib/python.py": "x=1", "src/good.py": "y=2"})
    paths = list(walk_paths(root, respect_gitignore=False))
    rel_paths = [os.path.relpath(p, root) for p in paths]
    assert not any(".venv" in p for p in rel_paths)
    assert any("good.py" in p for p in rel_paths)


def test_exclude_glob():
    root = _make_tree({"src/a.py": "x=1", "tests/t.py": "y=2"})
    paths = list(walk_paths(root, exclude_globs=["tests/*.py"], respect_gitignore=False))
    basenames = {os.path.basename(p) for p in paths}
    assert "a.py" in basenames
    assert "t.py" not in basenames


def test_include_glob():
    root = _make_tree({"src/a.py": "x=1", "other/b.py": "y=2"})
    paths = list(walk_paths(root, include_globs=["src/*.py"], respect_gitignore=False))
    basenames = {os.path.basename(p) for p in paths}
    assert "a.py" in basenames
    assert "b.py" not in basenames
