"""Hypothesis property tests for dont_be_lazy.

Strategies are deliberately realistic: identifiers that look like real
error codes, paths that look like real project paths, dates that fall in
plausible ranges. No absurd byte strings or astronomical integers.
"""

from __future__ import annotations

import string

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from dont_be_lazy.commands.stale_cmd import age_in_days, filter_stale, parse_age
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression
from dont_be_lazy.policy import check, check_all
from dont_be_lazy.reason import classify_reason
from dont_be_lazy.risk import score
from dont_be_lazy.scanners.python_comments import scan_python_comments

# ---------------------------------------------------------------------------
# Reusable strategies
# ---------------------------------------------------------------------------

# Error-code-looking strings: "F401", "E501", "B101", "reportMissingImport"
_ALPHA_UPPER = string.ascii_uppercase
_DIGITS = string.digits

_simple_code = st.one_of(
    # short uppercase+digit codes like F401, E501, W503, B602
    st.builds(
        lambda p, n: f"{p}{n}",
        st.text(_ALPHA_UPPER, min_size=1, max_size=2),
        st.integers(min_value=1, max_value=9999).map(str),
    ),
    # camelCase pyright-style codes
    st.from_regex(r"[a-z][a-zA-Z]{3,15}", fullmatch=True),
)

_code_list = st.lists(_simple_code, min_size=0, max_size=5)

_tool_names = st.sampled_from(
    ["ruff", "flake8", "mypy", "pyright", "pylint", "bandit", "coverage", "black", "isort", "semgrep", "unknown"]
)

_kind_names = st.sampled_from(
    [
        "noqa-blanket",
        "noqa-specific",
        "file-noqa",
        "type-ignore-blanket",
        "type-ignore-specific",
        "nosec-blanket",
        "nosec-specific",
        "no-cover",
        "fmt-skip",
        "disable-line",
    ]
)

_scope_kinds = st.sampled_from(list(ScopeKind))
_risk_levels = st.sampled_from(list(RiskLevel))

_realistic_path = st.one_of(
    # Unix-style paths
    st.builds(
        lambda parts: "/".join(parts),
        st.lists(st.from_regex(r"[a-zA-Z0-9_\-]{1,20}", fullmatch=True), min_size=1, max_size=5),
    ).map(lambda p: f"src/{p}.py"),
    # Windows-style paths
    st.builds(
        lambda parts: "\\".join(parts),
        st.lists(st.from_regex(r"[a-zA-Z0-9_\-]{1,20}", fullmatch=True), min_size=1, max_size=5),
    ).map(lambda p: f"C:\\project\\{p}.py"),
)

_realistic_reason = st.one_of(
    st.none(),
    st.just("TODO: fix upstream"),
    st.just("expires: 2099-12-31"),
    st.just("PROJ-123 tracking issue"),
    st.just("https://github.com/org/repo/issues/1"),
    st.text(string.printable, min_size=1, max_size=80).filter(lambda s: s.strip()),
)

_flag_list = st.lists(
    st.sampled_from(["blanket-ignore", "file-wide", "unclosed-block-suppression", "suspicious", "config-level"]),
    min_size=0,
    max_size=3,
)


@st.composite
def suppression_strategy(draw):
    return Suppression(
        tool=draw(_tool_names),
        kind=draw(_kind_names),
        pattern="# noqa: F401",
        path=draw(_realistic_path),
        line=draw(st.integers(min_value=1, max_value=10000)),
        end_line=draw(st.one_of(st.none(), st.integers(min_value=1, max_value=10000))),
        scope=draw(_scope_kinds),
        codes=draw(_code_list),
        reason=draw(_realistic_reason),
        risk=draw(_risk_levels),
        flags=draw(_flag_list),
        text=draw(st.text(string.printable, min_size=1, max_size=120)),
    )


# ---------------------------------------------------------------------------
# Fingerprint / ID properties
# ---------------------------------------------------------------------------


@given(suppression_strategy())
@settings(max_examples=200)
def test_fingerprint_is_deterministic(s: Suppression):
    """Calling fingerprint() twice must return the same value."""
    assert s.fingerprint() == s.fingerprint()


@given(suppression_strategy())
@settings(max_examples=200)
def test_id_is_deterministic(s: Suppression):
    """The id field computed during __post_init__ must be stable."""
    # Re-create with same params to re-run __post_init__
    s2 = Suppression(
        tool=s.tool,
        kind=s.kind,
        pattern=s.pattern,
        path=s.path,
        line=s.line,
        end_line=s.end_line,
        scope=s.scope,
        codes=list(s.codes),
        reason=s.reason,
        risk=s.risk,
        flags=list(s.flags),
        text=s.text,
    )
    assert s.id == s2.id
    assert s.fingerprint() == s2.fingerprint()


@given(suppression_strategy())
@settings(max_examples=200)
def test_id_format(s: Suppression):
    """ID must be 'DBL' + 8 uppercase hex chars."""
    assert s.id.startswith("DBL")
    suffix = s.id[3:]
    assert len(suffix) == 8
    assert all(c in "0123456789ABCDEF" for c in suffix)


@given(suppression_strategy())
@settings(max_examples=200)
def test_fingerprint_is_64_hex_chars(s: Suppression):
    fp = s.fingerprint()
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


@given(
    st.text(string.printable, min_size=1, max_size=80),
    st.text(string.printable, min_size=1, max_size=80),
)
@settings(max_examples=100)
def test_different_text_different_fingerprint(text_a: str, text_b: str):
    """Two suppressions with different normalized text should (almost always) differ."""
    # Normalize ourselves to compare

    def norm(t):
        return " ".join(t.strip().split())

    assume(norm(text_a) != norm(text_b))

    a = Suppression(
        tool="ruff",
        kind="noqa-specific",
        pattern="# noqa: F401",
        path="src/foo.py",
        line=1,
        end_line=None,
        scope=ScopeKind.line,
        codes=["F401"],
        reason=None,
        risk=RiskLevel.medium,
        flags=[],
        text=text_a,
    )
    b = Suppression(
        tool="ruff",
        kind="noqa-specific",
        pattern="# noqa: F401",
        path="src/foo.py",
        line=1,
        end_line=None,
        scope=ScopeKind.line,
        codes=["F401"],
        reason=None,
        risk=RiskLevel.medium,
        flags=[],
        text=text_b,
    )
    assert a.fingerprint() != b.fingerprint()


@given(_realistic_path, _realistic_path)
@settings(max_examples=100)
def test_windows_forward_slash_same_fingerprint(path_with_backslash, _unused):
    """A path with backslashes produces same fingerprint as forward-slash version."""
    forward = path_with_backslash.replace("\\", "/")
    a = Suppression(
        tool="ruff",
        kind="noqa-specific",
        pattern="# noqa",
        path=path_with_backslash,
        line=1,
        end_line=None,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.medium,
        flags=[],
        text="x = 1  # noqa",
    )
    b = Suppression(
        tool="ruff",
        kind="noqa-specific",
        pattern="# noqa",
        path=forward,
        line=1,
        end_line=None,
        scope=ScopeKind.line,
        codes=[],
        reason=None,
        risk=RiskLevel.medium,
        flags=[],
        text="x = 1  # noqa",
    )
    assert a.fingerprint() == b.fingerprint()


# ---------------------------------------------------------------------------
# RiskLevel ordering properties
# ---------------------------------------------------------------------------


@given(_risk_levels, _risk_levels)
@settings(max_examples=50)
def test_risk_level_total_order(a: RiskLevel, b: RiskLevel):
    """Exactly one of a<b, a==b, a>b must hold."""
    lt = a < b
    eq = a == b
    gt = a > b
    assert (lt + eq + gt) == 1  # exactly one true


@given(_risk_levels)
@settings(max_examples=20)
def test_risk_level_reflexive(a: RiskLevel):
    assert a <= a
    assert a >= a
    assert not (a < a)
    assert not (a > a)


@given(_risk_levels, _risk_levels, _risk_levels)
@settings(max_examples=50)
def test_risk_level_transitive(a: RiskLevel, b: RiskLevel, c: RiskLevel):
    if a <= b and b <= c:
        assert a <= c


# ---------------------------------------------------------------------------
# Risk score properties
# ---------------------------------------------------------------------------


@given(suppression_strategy())
@settings(max_examples=200)
def test_score_always_returns_valid_level(s: Suppression):
    """score() must always return a valid RiskLevel."""
    result = score(s)
    assert result in list(RiskLevel)


@given(suppression_strategy())
@settings(max_examples=200)
def test_score_never_raises(s: Suppression):
    """score() must never raise on any well-formed Suppression."""
    score(s)


@given(suppression_strategy())
@settings(max_examples=100)
def test_score_monotone_with_unclosed_flag(s: Suppression):
    """Adding 'unclosed-block-suppression' must not lower the score."""
    without = Suppression(
        tool=s.tool,
        kind=s.kind,
        pattern=s.pattern,
        path=s.path,
        line=s.line,
        end_line=s.end_line,
        scope=s.scope,
        codes=list(s.codes),
        reason=s.reason,
        risk=s.risk,
        flags=[f for f in s.flags if f != "unclosed-block-suppression"],
        text=s.text,
    )
    with_flag = Suppression(
        tool=s.tool,
        kind=s.kind,
        pattern=s.pattern,
        path=s.path,
        line=s.line,
        end_line=s.end_line,
        scope=s.scope,
        codes=list(s.codes),
        reason=s.reason,
        risk=s.risk,
        flags=[*list(s.flags), "unclosed-block-suppression"],
        text=s.text,
    )
    assert score(with_flag) >= score(without)


# ---------------------------------------------------------------------------
# Reason classification properties
# ---------------------------------------------------------------------------


@given(st.text(string.printable, min_size=0, max_size=200))
@settings(max_examples=300)
def test_classify_reason_always_returns_valid_quality(text: str):
    """classify_reason must return a known quality value for any printable string."""
    _, quality = classify_reason(text)
    assert quality in ("none", "placeholder", "plain-text", "issue-link", "expiry")


@given(st.text(string.printable, min_size=1, max_size=200).filter(lambda s: s.strip()))
@settings(max_examples=200)
def test_classify_reason_non_empty_not_none(text: str):
    """A non-empty, non-whitespace reason must not produce quality='none'."""
    _, quality = classify_reason(text)
    assert quality != "none"


@given(st.none() | st.just("") | st.just("   "))
@settings(max_examples=10)
def test_classify_reason_empty_is_none(text):
    _, quality = classify_reason(text)
    assert quality == "none"


@given(st.text(string.printable, min_size=1, max_size=200).filter(lambda s: s.strip()))
@settings(max_examples=200)
def test_classify_reason_returned_text_stripped(text: str):
    returned_text, quality = classify_reason(text)
    if quality != "none":
        assert returned_text == text.strip()


# ---------------------------------------------------------------------------
# Policy engine properties
# ---------------------------------------------------------------------------


@given(suppression_strategy())
@settings(max_examples=300)
def test_check_never_raises(s: Suppression):
    """check() must never raise on a well-formed Suppression."""
    check(s)


@given(suppression_strategy())
@settings(max_examples=300)
def test_check_returns_list(s: Suppression):
    violations = check(s)
    assert isinstance(violations, list)


@given(suppression_strategy())
@settings(max_examples=100)
def test_check_violation_rule_ids_valid(s: Suppression):
    """All returned rule IDs must be in the DBL001-DBL015 range."""
    violations = check(s)
    for v in violations:
        assert v.rule_id.startswith("DBL")
        num = int(v.rule_id[3:])
        assert 1 <= num <= 15


@given(suppression_strategy())
@settings(max_examples=100)
def test_check_violation_references_same_suppression(s: Suppression):
    """Each violation must reference the suppression that triggered it."""
    violations = check(s)
    for v in violations:
        assert v.suppression is s


@given(st.lists(suppression_strategy(), min_size=0, max_size=20))
@settings(max_examples=50)
def test_check_all_total_equals_sum_of_individual(findings: list[Suppression]):
    """check_all must produce the same result as summing check() per finding."""
    total = check_all(findings)
    individual = [v for s in findings for v in check(s)]
    assert len(total) == len(individual)


# ---------------------------------------------------------------------------
# parse_age properties
# ---------------------------------------------------------------------------


@given(st.integers(min_value=0, max_value=9999))
@settings(max_examples=100)
def test_parse_age_days_roundtrip(n: int):
    assert parse_age(f"{n}d") == n


@given(st.integers(min_value=0, max_value=999))
@settings(max_examples=100)
def test_parse_age_months_multiply_by_30(n: int):
    assert parse_age(f"{n}m") == n * 30


@given(st.integers(min_value=0, max_value=100))
@settings(max_examples=50)
def test_parse_age_years_multiply_by_365(n: int):
    assert parse_age(f"{n}y") == n * 365


# ---------------------------------------------------------------------------
# age_in_days properties
# ---------------------------------------------------------------------------


@given(st.dates(min_value=__import__("datetime").date(2000, 1, 1), max_value=__import__("datetime").date(2030, 12, 31)))
@settings(max_examples=100)
def test_age_in_days_consistent_with_today(d):
    import datetime

    result = age_in_days(d.isoformat())
    expected = (datetime.date.today() - d).days
    assert result == expected


@given(st.text(string.printable, min_size=1, max_size=30).filter(lambda s: not s.strip().startswith("2")))
@settings(max_examples=50)
def test_age_in_days_garbage_returns_zero(s: str):
    """Strings that clearly aren't dates should return 0 without raising."""
    result = age_in_days(s)
    assert result == 0


# ---------------------------------------------------------------------------
# filter_stale properties
# ---------------------------------------------------------------------------


@given(
    st.lists(suppression_strategy(), min_size=0, max_size=20),
    st.integers(min_value=0, max_value=3650),
)
@settings(max_examples=100)
def test_filter_stale_subset_of_input(findings, threshold):
    """filter_stale must return a subset of the input list."""
    result = filter_stale(findings, threshold, include_unknown=True)
    for s in result:
        assert s in findings


@given(st.lists(suppression_strategy(), min_size=0, max_size=20))
@settings(max_examples=50)
def test_filter_stale_zero_days_keeps_old(findings):
    """With threshold=0, all dated items should be included (age >= 0)."""
    result = filter_stale(findings, 0, include_unknown=False)
    for s in result:
        assert s.first_seen is not None


@given(st.lists(suppression_strategy(), min_size=0, max_size=20))
@settings(max_examples=50)
def test_filter_stale_include_unknown_keeps_dateless(findings):
    result = filter_stale(findings, 99999, include_unknown=True)
    for s in result:
        # Only dateless items can pass a 99999-day threshold
        assert s.first_seen is None


# ---------------------------------------------------------------------------
# scan_python_comments properties
# ---------------------------------------------------------------------------


@given(
    st.lists(
        st.sampled_from(
            [
                "x = 1  # noqa: F401\n",
                "x = 1  # noqa\n",
                "x = 1  # type: ignore\n",
                "x = 1  # type: ignore[attr-defined]\n",
                "x = bad()  # nosec\n",
                "# fmt: off\n",
                "# fmt: on\n",
                "# pylint: disable=missing-docstring\n",
                "# pylint: enable=missing-docstring\n",
                "x = 1\n",
                "# this is a regular comment\n",
            ]
        ),
        min_size=0,
        max_size=30,
    )
)
@settings(max_examples=200)
def test_scan_never_raises_on_realistic_lines(lines: list[str]):
    """scan_python_comments must never raise on any combination of real-world lines."""
    source = "".join(lines)
    result = scan_python_comments("test.py", source)
    assert isinstance(result, list)


@given(
    st.lists(
        st.sampled_from(
            [
                "x = 1  # noqa: F401\n",
                "x = 1  # noqa\n",
                "x = 1  # type: ignore\n",
                "x = bad()  # nosec\n",
                "# fmt: off\n",
                "# fmt: on\n",
                "x = 1\n",
            ]
        ),
        min_size=1,
        max_size=20,
    )
)
@settings(max_examples=100)
def test_scan_line_numbers_within_source_range(lines: list[str]):
    """Every finding's line number must be within bounds of the source."""
    source = "".join(lines)
    total_lines = source.count("\n") + (1 if not source.endswith("\n") else 0)
    result = scan_python_comments("test.py", source)
    for s in result:
        assert 1 <= s.line <= total_lines + 1  # +1 for edge cases


@given(
    st.lists(
        st.sampled_from(
            [
                "x = 1  # noqa: F401\n",
                "# fmt: off\n",
                "# fmt: on\n",
                "# pylint: disable=missing-docstring\n",
                "# pylint: enable=missing-docstring\n",
                "x = 1\n",
            ]
        ),
        min_size=0,
        max_size=20,
    )
)
@settings(max_examples=100)
def test_scan_all_findings_have_string_path(lines: list[str]):
    source = "".join(lines)
    result = scan_python_comments("myfile.py", source)
    for s in result:
        assert isinstance(s.path, str)
        assert s.path == "myfile.py"


@given(
    # Inject noqa into a realistic Python source line
    st.from_regex(r"[a-z_]+ = [a-z_]+\(\)", fullmatch=True),
    _code_list.filter(lambda codes: len(codes) > 0),
)
@settings(max_examples=100)
def test_noqa_specific_captures_codes(stmt: str, codes: list[str]):
    """noqa: with explicit codes must produce noqa-specific with those codes."""
    code_str = ", ".join(codes)
    source = f"{stmt}  # noqa: {code_str}\n"
    findings = scan_python_comments("test.py", source)
    specific = [s for s in findings if s.kind == "noqa-specific"]
    assert len(specific) >= 1
    found_codes = specific[0].codes
    for c in codes:
        assert c.upper() in [fc.upper() for fc in found_codes]


@given(st.text(string.printable.replace('"', "").replace("'", ""), min_size=1, max_size=80))
@settings(max_examples=100)
def test_scan_does_not_flag_string_literals(content: str):
    """Content inside a string literal must not be flagged as a suppression comment."""
    # Avoid newlines which would break the string literal
    safe_content = content.replace("\n", " ").replace("\\", "\\\\")
    source = f'x = "{safe_content}"\n'
    findings = scan_python_comments("test.py", source)
    # The string must not produce any findings (it's not a comment)
    assert findings == []
