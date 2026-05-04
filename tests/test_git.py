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
    monkeypatch.setattr(git, "_run", lambda args, cwd, timeout=15: output)

    info = git.blame_line("src\\mod.py", 2, "C:\\repo")

    assert info == {
        "author": "Jane Dev",
        "email": "jane@example.com",
        "date": "2024-01-01",
    }


def test_first_seen_by_log_uses_earliest_date(monkeypatch) -> None:
    monkeypatch.setattr(
        git,
        "_run",
        lambda args, cwd, timeout=15: "2025-02-03 00:00:00 +0000\n2023-04-05 00:00:00 +0000\n",
    )

    assert git.first_seen_by_log("src\\mod.py", "# noqa", "C:\\repo") == "2023-04-05"


def test_changed_files_since_strips_blank_lines(monkeypatch) -> None:
    monkeypatch.setattr(git, "_run", lambda args, cwd, timeout=15: "a.py\nb.py\n\n")

    assert git.changed_files_since("HEAD~1", "C:\\repo") == ["a.py", "b.py"]


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
    monkeypatch.setattr(git, "_run", lambda args, cwd, timeout=15: diff_output)

    assert git.diff_hunks_since("HEAD~1", "src\\mod.py", "C:\\repo") == [(3, 4), (20, 20)]
