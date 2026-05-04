"""Tests for the file walker."""

import os
import tempfile

from dont_be_lazy.walker import walk_paths


def _make_tree(files: dict[str, str]) -> str:
    root = tempfile.mkdtemp()
    for rel, content in files.items():
        abs_path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
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


def test_walk_custom_extensions(tmp_path):
    a = tmp_path / "a.py"
    a.write_text("x=1")
    b = tmp_path / "b.custom"
    b.write_text("y=2")
    paths = list(walk_paths(str(tmp_path), extensions={".custom"}, respect_gitignore=False))
    assert len(paths) == 1
    assert paths[0].endswith("b.custom")


def test_walk_respect_gitignore(tmp_path, monkeypatch):
    import dont_be_lazy.walker
    a = tmp_path / "a.py"
    a.write_text("x=1")
    b = tmp_path / "b.py"
    b.write_text("y=2")

    # Mock git ls-files to only include a.py
    monkeypatch.setattr(dont_be_lazy.walker, "_gitignored_files", lambda root: {"a.py"})

    paths = list(walk_paths(str(tmp_path), respect_gitignore=True))
    assert len(paths) == 1
    assert paths[0].endswith("a.py")


def test_gitignored_files_timeout(monkeypatch):
    import subprocess
    from dont_be_lazy.walker import _gitignored_files
    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 10)
    monkeypatch.setattr(subprocess, "run", mock_run)
    assert _gitignored_files(".") is None


def test_gitignored_files_exception(monkeypatch):
    import subprocess
    from dont_be_lazy.walker import _gitignored_files
    def mock_run(*args, **kwargs):
        raise FileNotFoundError()
    monkeypatch.setattr(subprocess, "run", mock_run)
    assert _gitignored_files(".") is None


def test_include_glob():
    root = _make_tree({"src/a.py": "x=1", "other/b.py": "y=2"})
    paths = list(walk_paths(root, include_globs=["src/*.py"], respect_gitignore=False))
    basenames = {os.path.basename(p) for p in paths}
    assert "a.py" in basenames
    assert "b.py" not in basenames
