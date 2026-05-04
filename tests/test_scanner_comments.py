"""Tests for the Python comment token scanner."""

import os

from dont_be_lazy.scanners.python_comments import scan_python_comments

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_comments.py")


def _scan(source: str):
    return scan_python_comments("test.py", source)


def test_noqa_blanket():
    findings = _scan("x = 1  # noqa\n")
    assert any(s.kind == "noqa-blanket" for s in findings)


def test_noqa_specific():
    findings = _scan("x = 1  # noqa: F401\n")
    kinds = [s.kind for s in findings]
    assert "noqa-specific" in kinds
    match = next(s for s in findings if s.kind == "noqa-specific")
    assert "F401" in match.codes


def test_no_flag_string_contents():
    source = 'text = "# noqa"\n'
    findings = _scan(source)
    assert not findings, f"Should not flag string content, got {findings}"


def test_no_flag_docstring():
    source = '"""Use # type: ignore here."""\n'
    findings = _scan(source)
    assert not findings


def test_type_ignore_blanket():
    findings = _scan("x = thing  # type: ignore\n")
    assert any(s.kind == "type-ignore-blanket" for s in findings)


def test_type_ignore_specific():
    findings = _scan("x = thing  # type: ignore[attr-defined]\n")
    match = next((s for s in findings if s.kind == "type-ignore-specific"), None)
    assert match is not None
    assert "attr-defined" in match.codes


def test_nosec_blanket():
    findings = _scan("x = bad()  # nosec\n")
    assert any(s.kind == "nosec-blanket" for s in findings)


def test_nosec_specific():
    findings = _scan("x = bad()  # nosec B602\n")
    match = next((s for s in findings if s.kind == "nosec-specific"), None)
    assert match is not None
    assert "B602" in match.codes


def test_pragma_no_cover():
    findings = _scan("if debug:  # pragma: no cover\n    pass\n")
    assert any(s.kind == "no-cover" for s in findings)


def test_pragma_no_branch():
    findings = _scan("if x:  # pragma: no branch\n    pass\n")
    assert any(s.kind == "no-branch" for s in findings)


def test_fmt_off_on_block():
    source = "# fmt: off\nx = 1\n# fmt: on\n"
    findings = _scan(source)
    fmt = next((s for s in findings if s.kind == "fmt-off-block"), None)
    assert fmt is not None
    assert fmt.end_line == 3


def test_fmt_off_unclosed():
    source = "# fmt: off\nx = 1\n"
    findings = _scan(source)
    fmt = next((s for s in findings if s.kind == "fmt-off-block"), None)
    assert fmt is not None
    assert "unclosed-block-suppression" in fmt.flags


def test_isort_skip():
    findings = _scan("import os  # isort: skip\n")
    assert any(s.kind == "skip-line" for s in findings)


def test_isort_skip_file():
    findings = _scan("# isort: skip_file\n")
    assert any(s.kind == "skip-file" for s in findings)


def test_pylint_disable_all_critical():
    findings = _scan("# pylint: disable=all\n")
    match = next((s for s in findings if s.tool == "pylint"), None)
    assert match is not None
    from dont_be_lazy.models import RiskLevel

    assert match.risk == RiskLevel.critical


def test_pyright_ignore_specific():
    findings = _scan("x = 1  # pyright: ignore[reportUnknownMemberType]\n")
    match = next((s for s in findings if s.tool == "pyright"), None)
    assert match is not None
    assert "reportUnknownMemberType" in match.codes


def test_ruff_noqa_file_wide():
    findings = _scan("# ruff: noqa\n")
    match = next((s for s in findings if s.kind == "file-noqa"), None)
    assert match is not None


def test_flake8_noqa_file_wide():
    findings = _scan("# flake8: noqa\n")
    match = next((s for s in findings if s.tool == "flake8" and s.kind == "file-noqa"), None)
    assert match is not None


def test_fixture_file():
    with open(FIXTURE, encoding="utf-8") as f:
        source = f.read()
    findings = scan_python_comments(FIXTURE, source)
    tools = {s.tool for s in findings}
    assert "ruff" in tools
    assert "mypy" in tools
    assert "bandit" in tools
    assert "coverage" in tools
