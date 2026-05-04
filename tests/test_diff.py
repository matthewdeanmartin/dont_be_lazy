"""Tests for git diff helpers."""

from __future__ import annotations

from dont_be_lazy.diff import build_diff_index, files_changed_since, suppression_in_diff


def test_files_changed_since_returns_absolute_paths(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("dont_be_lazy.diff.changed_files_since", lambda ref, cwd: ["src\\a.py", "pyproject.toml"])

    changed = files_changed_since("HEAD~1", str(tmp_path))

    assert changed == {
        str(tmp_path / "src" / "a.py"),
        str(tmp_path / "pyproject.toml"),
    }


def test_suppression_in_diff_checks_hunks() -> None:
    assert suppression_in_diff(10, [(1, 5), (10, 12)])
    assert not suppression_in_diff(9, [(1, 5), (10, 12)])


def test_build_diff_index_only_keeps_changed_files(monkeypatch, tmp_path) -> None:
    first = str(tmp_path / "src" / "a.py")
    second = str(tmp_path / "src" / "b.py")
    monkeypatch.setattr(
        "dont_be_lazy.diff.diff_hunks_since",
        lambda ref, path, cwd: [(3, 5)] if path.endswith("a.py") else [],
    )

    index = build_diff_index("HEAD~1", [first, second], str(tmp_path))

    assert index == {first: [(3, 5)]}
