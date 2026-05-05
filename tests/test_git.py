"""Tests for git integration helpers."""

from __future__ import annotations

from dont_be_lazy import git


def test_blame_line_parses_porcelain(monkeypatch) -> None:
    output = "\n".join(
        [
            "0123456789012345678901234567890123456789 2 2 1",
            "author Jane Dev",
            "author-mail <jane@example.com>",
            "author-time 1704067200",
            "\tvalue = 1  # noqa",
        ]
    )
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: output)

    info = git.blame_line("src\\mod.py", 2, "C:\\repo")

    assert info == {
        "author": "Jane Dev",
        "email": "jane@example.com",
        "date": "2024-01-01",
    }


def test_first_seen_by_log_uses_earliest_date(monkeypatch) -> None:
    monkeypatch.setattr(
        git,
        "run",
        lambda args, cwd, timeout=15: "2025-02-03 00:00:00 +0000\n2023-04-05 00:00:00 +0000\n",
    )

    assert git.first_seen_by_log("src\\mod.py", "# noqa", "C:\\repo") == "2023-04-05"


def test_changed_files_since_strips_blank_lines(monkeypatch) -> None:
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: "a.py\nb.py\n\n")

    assert git.changed_files_since("HEAD~1", "C:\\repo") == ["a.py", "b.py"]


def test_run_real_git() -> None:
    # Test run with a real git command in the current repo
    import os

    res = git.run([git.GIT_BIN, "rev-parse", "--is-inside-work-tree"], cwd=os.getcwd())
    assert res and "true" in res.lower()


def test_is_git_repo(monkeypatch) -> None:
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: "true" if "--git-dir" in args else None)
    assert git.is_git_repo(".") is True
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: None)
    assert git.is_git_repo(".") is False


def test_blame_lines_multiple(monkeypatch) -> None:
    output = "\n".join(
        [
            "0123456789012345678901234567890123456789 2 2 1",
            "author Jane Dev",
            "author-mail <jane@example.com>",
            "author-time 1704067200",
            "\tline 2",
            "abcdefabcdefabcdefabcdefabcdefabcdefabcd 5 5 1",
            "author John Doe",
            "author-mail <john@example.com>",
            "author-time 1704153600",
            "\tline 5",
        ]
    )
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: output)

    res = git.blame_lines("file.py", [2, 5], ".")
    assert res[2]["author"] == "Jane Dev"
    assert res[5]["author"] == "John Doe"
    assert res[2]["date"] == "2024-01-01"
    assert res[5]["date"] == "2024-01-02"


def test_blame_lines_empty_input() -> None:
    assert git.blame_lines("file.py", [], ".") == {}


def test_blame_lines_no_output(monkeypatch) -> None:
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: None)
    assert git.blame_lines("file.py", [1], ".") == {}


def test_first_seen_by_log_fallback(monkeypatch) -> None:
    def mock_run(args, cwd, timeout=15):
        if "--follow" in args:
            return None  # First call fails
        return "2023-01-01 00:00:00 +0000"

    monkeypatch.setattr(git, "run", mock_run)
    assert git.first_seen_by_log("file.py", "text", ".") == "2023-01-01"


def test_first_seen_by_log_no_dates(monkeypatch) -> None:
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: "not a date")
    assert git.first_seen_by_log("file.py", "text", ".") is None


def test_diff_hunks_since_no_output(monkeypatch) -> None:
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: None)
    assert git.diff_hunks_since("HEAD", "file.py", ".") == []


def test_blame_line_no_output(monkeypatch) -> None:
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: None)
    assert git.blame_line("file.py", 1, ".") is None


def test_first_seen_by_log_no_output(monkeypatch) -> None:
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: None)
    assert git.first_seen_by_log("file.py", "text", ".") is None


def test_changed_files_since_no_output(monkeypatch) -> None:
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: None)
    assert git.changed_files_since("HEAD", ".") == []


def test_run_exception(monkeypatch) -> None:
    import subprocess

    def mock_run(*args, **kwargs):
        raise OSError("spawn failed")

    monkeypatch.setattr(subprocess, "run", mock_run)
    assert git.run(["git"], ".") is None


def test_diff_hunks_since_parses_multiple_hunks(monkeypatch) -> None:
    diff_output = "\n".join(
        [
            "@@ -1,0 +3,2 @@",
            "+first",
            "+second",
            "@@ -10 +20 @@",
            "+third",
        ]
    )
    monkeypatch.setattr(git, "run", lambda args, cwd, timeout=15: diff_output)

    assert git.diff_hunks_since("HEAD~1", "src\\mod.py", "C:\\repo") == [(3, 4), (20, 20)]
