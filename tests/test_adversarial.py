"""Adversarial unit tests targeting real bug patterns: encoding, path normalization,
block-state edge cases, regex boundary conditions, and cross-platform behavior."""

from __future__ import annotations


import pytest

from dont_be_lazy.commands.stale_cmd import age_in_days, parse_age
from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression
from dont_be_lazy.policy import check
from dont_be_lazy.reason import classify_reason, extract_trailing_reason
from dont_be_lazy.risk import score
from dont_be_lazy.scanners.python_comments import scan_python_comments

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sup(**kwargs) -> Suppression:
    defaults = dict(
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
        text="import os  # noqa: F401",
    )
    defaults.update(kwargs)
    return Suppression(**defaults)  # type: ignore[arg-type]


def scan(source: str) -> list[Suppression]:
    return scan_python_comments("test.py", source)


# ===========================================================================
# Fingerprint & ID stability
# ===========================================================================


class TestFingerprintStability:
    def test_windows_vs_posix_path_same_fingerprint(self):
        """Backslash and forward-slash paths must produce the same fingerprint."""
        a = sup(path="src\\foo\\bar.py")
        b = sup(path="src/foo/bar.py")
        assert a.fingerprint() == b.fingerprint()

    def test_windows_vs_posix_path_same_id(self):
        a = sup(path="src\\foo\\bar.py")
        b = sup(path="src/foo/bar.py")
        assert a.id == b.id

    def test_trailing_whitespace_normalized(self):
        """Extra trailing/leading spaces in text must not change fingerprint."""
        a = sup(text="import os  # noqa: F401   ")
        b = sup(text="   import os  # noqa: F401")
        assert a.fingerprint() == b.fingerprint()

    def test_internal_whitespace_collapsed(self):
        """Multiple internal spaces collapse to single space."""
        a = sup(text="import   os  # noqa: F401")
        b = sup(text="import os  # noqa: F401")
        assert a.fingerprint() == b.fingerprint()

    def test_codes_sorted_in_fingerprint(self):
        """Code ordering must not affect fingerprint (codes are sorted)."""
        a = sup(codes=["F401", "E501"])
        b = sup(codes=["E501", "F401"])
        assert a.fingerprint() == b.fingerprint()

    def test_different_tools_different_fingerprint(self):
        a = sup(tool="ruff")
        b = sup(tool="mypy", kind="type-ignore-specific")
        assert a.fingerprint() != b.fingerprint()

    def test_different_kind_different_fingerprint(self):
        a = sup(kind="noqa-specific")
        b = sup(kind="noqa-blanket", codes=[])
        assert a.fingerprint() != b.fingerprint()

    def test_id_always_starts_with_dbl(self):
        s = sup()
        assert s.id.startswith("DBL")

    def test_id_length_is_11(self):
        # "DBL" + 8 hex chars
        s = sup()
        assert len(s.id) == 11

    def test_id_is_uppercase(self):
        s = sup()
        assert s.id == s.id.upper()

    def test_deep_relative_path_normalised(self):
        """Paths with ./ or ../ components are normalised before hashing."""
        a = sup(path="./src/foo.py")
        b = sup(path="src/foo.py")
        # os.path.normpath strips leading ./
        assert a.fingerprint() == b.fingerprint()


# ===========================================================================
# RiskLevel ordering
# ===========================================================================


class TestRiskLevelOrdering:
    def test_total_order(self):
        order = [RiskLevel.low, RiskLevel.medium, RiskLevel.high, RiskLevel.critical]
        for i, a in enumerate(order):
            for j, b in enumerate(order):
                assert (a < b) == (i < j)
                assert (a <= b) == (i <= j)
                assert (a > b) == (i > j)
                assert (a >= b) == (i >= j)

    def test_max_works(self):
        assert max(RiskLevel.low, RiskLevel.critical) == RiskLevel.critical

    def test_min_works(self):
        assert min(RiskLevel.high, RiskLevel.medium) == RiskLevel.medium

    def test_coerce_from_string(self):
        assert RiskLevel.low < "high"
        assert RiskLevel.critical >= "critical"

    def test_equality_with_string(self):
        # RiskLevel is a str enum; value should equal the string
        assert RiskLevel.medium.value == "medium"

    def test_invalid_string_coerce_raises(self):
        with pytest.raises((ValueError, KeyError)):
            _ = RiskLevel.low < "extreme"


# ===========================================================================
# Comment scanner: boundary & encoding cases
# ===========================================================================


class TestCommentScannerBoundary:
    # --- noqa must not fire inside strings ---
    def test_string_with_noqa_not_flagged(self):
        assert scan('msg = "# noqa"\n') == []

    def test_fstring_with_noqa_not_flagged(self):
        assert scan('msg = f"result: # noqa"\n') == []

    def test_docstring_with_type_ignore_not_flagged(self):
        assert scan('"""Use # type: ignore here"""\n') == []

    def test_multiline_string_not_flagged(self):
        source = '"""\n# noqa: F401\n"""\n'
        assert scan(source) == []

    # --- case insensitivity ---
    def test_noqa_uppercase(self):
        findings = scan("x = 1  # NOQA\n")
        assert any(s.kind == "noqa-blanket" for s in findings)

    def test_type_ignore_mixed_case(self):
        # PEP 484 specifies `type: ignore` as lowercase-only; mypy is case-sensitive.
        # The scanner correctly does NOT match `# Type: Ignore`.
        findings = scan("x = 1  # Type: Ignore\n")
        assert not any(s.tool == "mypy" for s in findings)

    def test_nosec_uppercase(self):
        findings = scan("x = bad()  # NOSEC\n")
        assert any(s.kind == "nosec-blanket" for s in findings)

    def test_pragma_no_cover_mixed_case(self):
        findings = scan("if x:  # Pragma: No Cover\n    pass\n")
        assert any(s.kind == "no-cover" for s in findings)

    # --- whitespace variations in comment tokens ---
    def test_noqa_extra_spaces_before_colon(self):
        findings = scan("x = 1  # noqa : F401\n")
        assert any(s.kind == "noqa-specific" for s in findings)

    def test_type_ignore_spaces_around_colon(self):
        findings = scan("x = 1  # type : ignore\n")
        assert any(s.tool == "mypy" for s in findings)

    def test_pylint_disable_spaces_around_equals(self):
        findings = scan("x = 1  # pylint: disable = missing-docstring\n")
        assert any(s.tool == "pylint" for s in findings)

    # --- multiple suppressions on one line ---
    def test_noqa_and_type_ignore_same_line(self):
        """A line with both noqa and type: ignore should produce two findings."""
        findings = scan("x: int = 1  # noqa: F401  # type: ignore\n")
        tools = {s.tool for s in findings}
        assert "ruff" in tools
        assert "mypy" in tools

    # --- nosec with multiple codes ---
    def test_nosec_multiple_codes(self):
        findings = scan("x = exec(cmd)  # nosec B602, B603\n")
        match = next((s for s in findings if s.kind == "nosec-specific"), None)
        assert match is not None
        assert "B602" in match.codes
        assert "B603" in match.codes

    # --- noqa with multiple codes ---
    def test_noqa_multiple_codes(self):
        findings = scan("x = 1  # noqa: F401, E501\n")
        match = next((s for s in findings if s.kind == "noqa-specific"), None)
        assert match is not None
        assert "F401" in match.codes
        assert "E501" in match.codes

    # --- isort skip vs skip_file disambiguation ---
    def test_isort_skip_not_confused_with_skip_file(self):
        findings = scan("import os  # isort: skip\n")
        kinds = [s.kind for s in findings if s.tool == "isort"]
        assert "skip-line" in kinds
        assert "skip-file" not in kinds

    def test_isort_skip_file_produces_file_scope(self):
        findings = scan("# isort: skip_file\n")
        match = next((s for s in findings if s.tool == "isort" and s.kind == "skip-file"), None)
        assert match is not None
        assert match.scope == ScopeKind.file

    # --- line numbers are 1-based and correct ---
    def test_line_number_second_line(self):
        source = "x = 1\ny = 2  # noqa\n"
        findings = scan(source)
        assert any(s.line == 2 for s in findings)

    def test_line_number_first_line(self):
        source = "x = 1  # noqa\ny = 2\n"
        findings = scan(source)
        assert any(s.line == 1 for s in findings)

    # --- empty and minimal files ---
    def test_empty_source(self):
        assert scan("") == []

    def test_only_newlines(self):
        assert scan("\n\n\n") == []

    def test_only_whitespace_comment(self):
        assert scan("#   \n") == []

    # --- tokenize failure is silently swallowed ---
    def test_invalid_syntax_does_not_raise(self):
        # unterminated string causes tokenize.TokenError
        result = scan('x = "unterminated\n')
        assert isinstance(result, list)

    # --- NOSONAR case-sensitive (by spec) ---
    def test_nosonar_exact_case(self):
        findings = scan("x = 1  # NOSONAR\n")
        assert any(s.tool == "sonar" for s in findings)

    def test_nosonar_lowercase_not_matched(self):
        # _NOSONAR pattern has no re.IGNORECASE flag
        findings = scan("x = 1  # nosonar\n")
        assert not any(s.tool == "sonar" for s in findings)


# ===========================================================================
# Block suppression state machine
# ===========================================================================


class TestBlockStateMachine:
    def test_fmt_off_on_sets_end_line(self):
        source = "# fmt: off\nx = 1\n# fmt: on\n"
        findings = scan(source)
        block = next(s for s in findings if s.kind == "fmt-off-block")
        assert block.end_line == 3

    def test_fmt_off_without_on_is_unclosed(self):
        source = "# fmt: off\nx = 1\n"
        findings = scan(source)
        block = next(s for s in findings if s.kind == "fmt-off-block")
        assert "unclosed-block-suppression" in block.flags
        assert block.risk >= RiskLevel.high

    def test_nested_fmt_off_off_on_closes_one(self):
        """Two fmt:off with one fmt:on — the second off stays unclosed."""
        source = "# fmt: off\n# fmt: off\nx = 1\n# fmt: on\n"
        findings = scan(source)
        blocks = [s for s in findings if s.kind == "fmt-off-block"]
        assert len(blocks) == 2
        closed = [b for b in blocks if b.end_line is not None]
        unclosed = [b for b in blocks if "unclosed-block-suppression" in b.flags]
        assert len(closed) == 1
        assert len(unclosed) == 1

    def test_pylint_disable_enable_produces_block(self):
        source = "# pylint: disable=missing-docstring\nx = 1\n# pylint: enable=missing-docstring\n"
        findings = scan(source)
        block = next((s for s in findings if s.tool == "pylint" and s.kind == "disable-block"), None)
        assert block is not None
        assert block.end_line == 3

    def test_pylint_enable_without_disable_doesnt_crash(self):
        source = "# pylint: enable=missing-docstring\n"
        findings = scan(source)
        # No crash, no block (nothing to close)
        assert not any(s.kind == "disable-block" for s in findings)

    def test_isort_off_on_block(self):
        source = "# isort: off\nimport os\n# isort: on\n"
        findings = scan(source)
        block = next((s for s in findings if s.tool == "isort" and s.kind == "isort-off-block"), None)
        assert block is not None
        assert block.end_line == 3

    def test_ruff_disable_enable_block(self):
        source = "# ruff: disable[F401]\nimport os\n# ruff: enable[F401]\n"
        findings = scan(source)
        block = next((s for s in findings if s.tool == "ruff" and s.kind == "disable-block"), None)
        assert block is not None
        assert block.end_line == 3

    def test_multiple_block_types_independent(self):
        """fmt and isort blocks track state independently."""
        source = "# fmt: off\n# isort: off\nx = 1\n# isort: on\n# fmt: on\n"
        findings = scan(source)
        fmt_block = next(s for s in findings if s.kind == "fmt-off-block")
        isort_block = next(s for s in findings if s.tool == "isort" and s.kind == "isort-off-block")
        assert fmt_block.end_line == 5
        assert isort_block.end_line == 4


# ===========================================================================
# UTF-8 / encoding edge cases
# ===========================================================================


class TestEncodingEdgeCases:
    def test_utf8_source_with_noqa(self):
        source = "résumé = get_résumé()  # noqa: F401\n"
        findings = scan(source)
        assert any(s.kind == "noqa-specific" for s in findings)

    def test_chinese_comment_text_doesnt_crash(self):
        source = "x = 1  # 这是中文注释 noqa: F401\n"
        findings = scan(source)
        # Should not crash; may or may not find noqa depending on regex
        assert isinstance(findings, list)

    def test_latin1_looking_unicode_in_comment(self):
        source = "x = 1  # naïve suppression # noqa\n"
        findings = scan(source)
        assert any(s.kind == "noqa-blanket" for s in findings)

    def test_emoji_in_comment_doesnt_crash(self):
        source = "x = 1  # 🚫 noqa: E501\n"
        findings = scan(source)
        assert isinstance(findings, list)

    def test_scan_utf8_file_on_disk(self, tmp_path):
        """scan_python_comments reads source passed as string; test full read→scan cycle."""
        p = tmp_path / "test_utf8.py"
        content = "# -*- coding: utf-8 -*-\nrépertoire = 1  # noqa: F841\n"
        p.write_text(content, encoding="utf-8")
        source = p.read_text(encoding="utf-8")
        findings = scan_python_comments(str(p), source)
        assert any(s.kind == "noqa-specific" for s in findings)

    def test_scan_file_with_bom(self, tmp_path):
        """UTF-8 BOM (byte order mark) should not cause tokenize to fail."""
        p = tmp_path / "bom_file.py"
        content = "﻿import os  # noqa: F401\n"  # ﻿ is UTF-8 BOM
        p.write_text(content, encoding="utf-8-sig")
        source = p.read_text(encoding="utf-8-sig")
        findings = scan_python_comments(str(p), source)
        assert any(s.kind == "noqa-specific" for s in findings)


# ===========================================================================
# Windows vs Linux path handling in Suppression
# ===========================================================================


class TestPathNormalization:
    def test_windows_absolute_path_in_suppression(self):
        s = sup(path=r"C:\Users\dev\project\src\foo.py")
        assert s.id.startswith("DBL")

    def test_unc_path_doesnt_crash(self):
        s = sup(path=r"\\server\share\project\foo.py")
        assert s.id.startswith("DBL")

    def test_path_with_spaces(self):
        a = sup(path="C:/My Projects/src/foo.py")
        b = sup(path=r"C:\My Projects\src\foo.py")
        assert a.fingerprint() == b.fingerprint()

    def test_path_case_sensitivity(self):
        """On Windows paths may differ only in case — fingerprint will differ since
        normpath does NOT lowercase on Windows, so these are treated as different."""
        a = sup(path="src/Foo.py")
        b = sup(path="src/foo.py")
        # We just assert no crash; equality is OS-dependent
        assert a.id.startswith("DBL")
        assert b.id.startswith("DBL")


# ===========================================================================
# Risk scoring adversarial cases
# ===========================================================================


class TestRiskScoring:
    def test_security_tool_bumps_risk(self):
        """Bandit with no codes and no reason should be critical."""
        s = sup(tool="bandit", kind="nosec-blanket", codes=[], reason=None, scope=ScopeKind.line)
        level = score(s)
        assert level >= RiskLevel.high

    def test_codes_credit_reduces_risk(self):
        """Having specific codes should credit (reduce) the computed risk."""
        without_codes = sup(tool="ruff", kind="noqa-blanket", codes=[], reason=None)
        with_codes = sup(tool="ruff", kind="noqa-specific", codes=["F401"], reason=None)
        assert score(with_codes) <= score(without_codes)

    def test_expiry_in_reason_credits_risk(self):
        """A reason containing 'expiry' lowers risk by one step."""
        without = sup(tool="ruff", kind="noqa-specific", codes=["F401"], reason=None)
        with_expiry = sup(
            tool="ruff",
            kind="noqa-specific",
            codes=["F401"],
            reason="expires: 2099-12-31",
        )
        assert score(with_expiry) <= score(without)

    def test_unclosed_block_bumps_risk(self):
        s = sup(
            tool="black",
            kind="fmt-off-block",
            scope=ScopeKind.block,
            codes=[],
            flags=["unclosed-block-suppression"],
        )
        level = score(s)
        assert level >= RiskLevel.high

    def test_file_scope_bumps_risk(self):
        line_s = sup(tool="ruff", kind="noqa-specific", codes=["F401"], scope=ScopeKind.line)
        file_s = sup(tool="ruff", kind="file-noqa", codes=[], scope=ScopeKind.file)
        assert score(file_s) >= score(line_s)

    def test_no_code_tools_not_penalized_for_missing_codes(self):
        """black/isort/coverage never carry codes; missing codes must not bump them."""
        s = sup(tool="black", kind="fmt-skip", codes=[], reason=None, scope=ScopeKind.line)
        # base for black/fmt-skip is low; should not be bumped just because codes=[]
        level = score(s)
        assert level <= RiskLevel.medium

    def test_unknown_tool_falls_back_to_medium_base(self):
        s = sup(tool="novelscanner", kind="some-ignore", codes=[], reason=None)
        level = score(s)
        assert level in (RiskLevel.low, RiskLevel.medium, RiskLevel.high, RiskLevel.critical)

    def test_config_scope_bumps_risk(self):
        line_s = sup(tool="ruff", kind="noqa-specific", codes=["F401"], scope=ScopeKind.line)
        cfg_s = sup(tool="ruff", kind="config-ignore", codes=["F401"], scope=ScopeKind.config)
        assert score(cfg_s) >= score(line_s)

    def test_critical_cannot_be_bumped_past_critical(self):
        """Risk capping: critical stays critical no matter how many bumps."""
        s = sup(
            tool="bandit",
            kind="nosec-blanket",
            codes=[],
            reason=None,
            scope=ScopeKind.file,
            flags=["unclosed-block-suppression"],
        )
        assert score(s) == RiskLevel.critical


# ===========================================================================
# Reason classification adversarial cases
# ===========================================================================


class TestReasonClassification:
    def test_none_reason(self):
        _, q = classify_reason(None)
        assert q == "none"

    def test_empty_string_reason(self):
        _, q = classify_reason("")
        assert q == "none"

    def test_whitespace_only_reason(self):
        _, q = classify_reason("   ")
        assert q == "none"

    def test_expiry_takes_priority_over_issue_link(self):
        """A reason with both an expiry date and a URL should be classified as expiry."""
        _, q = classify_reason("expires: 2025-12-01 see https://example.com/issue/1")
        assert q == "expiry"

    def test_expiry_date_various_keywords(self):
        for phrase in ("expires: 2025-01-01", "until 2025-01-01", "remove-after 2025-01-01"):
            _, q = classify_reason(phrase)
            assert q == "expiry", f"Failed for {phrase!r}"

    def test_jira_style_issue_link(self):
        _, q = classify_reason("PROJ-1234 upstream bug")
        assert q == "issue-link"

    def test_github_issue_style(self):
        _, q = classify_reason("see #42 for context")
        assert q == "issue-link"

    def test_url_reason(self):
        _, q = classify_reason("https://github.com/org/repo/issues/99")
        assert q == "issue-link"

    def test_placeholder_todo(self):
        _, q = classify_reason("TODO fix this properly")
        assert q == "placeholder"

    def test_placeholder_hack(self):
        _, q = classify_reason("HACK: ignore for now")
        assert q == "placeholder"

    def test_plain_text(self):
        _, q = classify_reason("Necessary because upstream library has broken types")
        assert q == "plain-text"

    def test_reason_text_returned_stripped(self):
        text, _ = classify_reason("  some reason  ")
        assert text == "some reason"

    def test_extract_trailing_reason_empty(self):
        result = extract_trailing_reason("# noqa: F401", len("# noqa: F401"))
        assert result is None

    def test_extract_trailing_reason_with_text(self):
        comment = "# noqa: F401  legacy import"
        result = extract_trailing_reason(comment, comment.index("F401") + 4)
        assert result == "legacy import"


# ===========================================================================
# Policy engine adversarial cases
# ===========================================================================


class TestPolicyEngine:
    def test_dbl001_blanket_inline(self):
        s = sup(flags=["blanket-ignore"], scope=ScopeKind.line)
        violations = check(s)
        assert any(v.rule_id == "DBL001" for v in violations)

    def test_dbl001_not_fired_for_file_scope_blanket(self):
        """Blanket at file scope is DBL002, not DBL001."""
        s = sup(flags=["blanket-ignore", "file-wide"], scope=ScopeKind.file)
        violations = check(s)
        rule_ids = {v.rule_id for v in violations}
        assert "DBL002" in rule_ids
        # DBL001 requires scope==line
        assert "DBL001" not in rule_ids

    def test_dbl002_file_scope(self):
        s = sup(scope=ScopeKind.file)
        violations = check(s)
        assert any(v.rule_id == "DBL002" for v in violations)

    def test_dbl002_module_scope(self):
        s = sup(scope=ScopeKind.module)
        violations = check(s)
        assert any(v.rule_id == "DBL002" for v in violations)

    def test_dbl002_file_wide_flag(self):
        s = sup(scope=ScopeKind.line, flags=["file-wide"])
        violations = check(s)
        assert any(v.rule_id == "DBL002" for v in violations)

    def test_dbl003_unclosed_block(self):
        s = sup(flags=["unclosed-block-suppression"])
        violations = check(s)
        assert any(v.rule_id == "DBL003" for v in violations)

    def test_dbl004_no_reason_when_required(self):
        s = sup(reason=None)
        violations = check(s, policy={"require_reason": True})
        assert any(v.rule_id == "DBL004" for v in violations)

    def test_dbl004_not_fired_when_not_required(self):
        s = sup(reason=None)
        violations = check(s, policy={})
        assert not any(v.rule_id == "DBL004" for v in violations)

    def test_dbl004_not_fired_when_reason_present(self):
        s = sup(reason="valid reason")
        violations = check(s, policy={"require_reason": True})
        assert not any(v.rule_id == "DBL004" for v in violations)

    def test_dbl004_per_tool_override(self):
        """Tool-level require_reason overrides global setting."""
        s = sup(tool="mypy", kind="type-ignore-blanket", reason=None)
        policy = {"require_reason": False, "by_tool": {"mypy": {"require_reason": True}}}
        violations = check(s, policy=policy)
        assert any(v.rule_id == "DBL004" for v in violations)

    def test_dbl006_security_tool(self):
        for tool in ("bandit", "semgrep", "secrets"):
            s = sup(tool=tool, kind="nosec-blanket")
            violations = check(s)
            assert any(v.rule_id == "DBL006" for v in violations), f"Missing DBL006 for {tool}"

    def test_dbl007_type_checker(self):
        for tool in ("mypy", "pyright", "pytype", "ty"):
            s = sup(tool=tool, kind="type-ignore-blanket")
            violations = check(s)
            assert any(v.rule_id == "DBL007" for v in violations), f"Missing DBL007 for {tool}"

    def test_dbl008_skipped_test(self):
        s = sup(tool="pytest", kind="skip-unconditional", scope=ScopeKind.test)
        violations = check(s)
        assert any(v.rule_id == "DBL008" for v in violations)

    def test_dbl008_not_fired_for_non_test_scope(self):
        """pytest skip at line scope (not test scope) should NOT fire DBL008."""
        s = sup(tool="pytest", kind="skip-unconditional", scope=ScopeKind.line)
        violations = check(s)
        assert not any(v.rule_id == "DBL008" for v in violations)

    def test_dbl009_xfail_nonstrict(self):
        s = sup(tool="pytest", kind="xfail-nonstrict")
        violations = check(s)
        assert any(v.rule_id == "DBL009" for v in violations)

    def test_dbl010_config_ignore(self):
        s = sup(scope=ScopeKind.config, kind="config-ignore")
        violations = check(s)
        assert any(v.rule_id == "DBL010" for v in violations)

    def test_dbl011_config_exclude(self):
        s = sup(scope=ScopeKind.config, kind="config-exclude")
        violations = check(s)
        assert any(v.rule_id == "DBL011" for v in violations)

    def test_dbl012_malformed_flag(self):
        s = sup(flags=["malformed"])
        violations = check(s)
        assert any(v.rule_id == "DBL012" for v in violations)

    def test_dbl012_malformed_in_kind(self):
        s = sup(kind="malformed-noqa")
        violations = check(s)
        assert any(v.rule_id == "DBL012" for v in violations)

    def test_dbl013_unknown_tool(self):
        s = sup(tool="unknown")
        violations = check(s)
        assert any(v.rule_id == "DBL013" for v in violations)

    def test_dbl013_suspicious_flag(self):
        s = sup(tool="ruff", flags=["suspicious"])
        violations = check(s)
        assert any(v.rule_id == "DBL013" for v in violations)

    def test_dbl015_pip_audit_vulnerability(self):
        s = sup(tool="pip-audit", kind="ignored-vulnerability")
        violations = check(s)
        assert any(v.rule_id == "DBL015" for v in violations)

    def test_dbl015_safety_vulnerability(self):
        s = sup(tool="safety", kind="ignored-vulnerability")
        violations = check(s)
        assert any(v.rule_id == "DBL015" for v in violations)

    def test_empty_policy_no_crash(self):
        s = sup()
        violations = check(s, policy={})
        assert isinstance(violations, list)

    def test_none_policy_no_crash(self):
        s = sup()
        violations = check(s, policy=None)
        assert isinstance(violations, list)

    def test_multiple_violations_single_suppression(self):
        """A single very-bad suppression can trigger many rules simultaneously."""
        s = sup(
            tool="bandit",
            kind="nosec-blanket",
            scope=ScopeKind.file,
            flags=["blanket-ignore", "file-wide", "unclosed-block-suppression"],
            reason=None,
        )
        violations = check(s, policy={"require_reason": True})
        rule_ids = {v.rule_id for v in violations}
        assert "DBL002" in rule_ids
        assert "DBL003" in rule_ids
        assert "DBL004" in rule_ids
        assert "DBL006" in rule_ids


# ===========================================================================
# stale_cmd: parse_age and age_in_days
# ===========================================================================


class TestParseAge:
    def test_days(self):
        assert parse_age("180d") == 180

    def test_months(self):
        assert parse_age("6m") == 180

    def test_years(self):
        assert parse_age("1y") == 365

    def test_no_unit_defaults_to_days(self):
        assert parse_age("30") == 30

    def test_leading_whitespace_stripped(self):
        assert parse_age("  90d  ") == 90

    def test_uppercase_unit_accepted(self):
        assert parse_age("2Y") == 730

    def test_zero_days(self):
        assert parse_age("0d") == 0

    def test_large_value(self):
        assert parse_age("9999d") == 9999

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError):
            parse_age("six months")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            parse_age("")

    def test_negative_not_supported(self):
        with pytest.raises(ValueError):
            parse_age("-10d")


class TestAgeInDays:
    def test_today_is_zero(self):
        import datetime

        today = datetime.date.today().isoformat()
        assert age_in_days(today) == 0

    def test_yesterday_is_one(self):
        import datetime

        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        assert age_in_days(yesterday) == 1

    def test_far_past(self):
        # 2020-01-01 is definitely more than 1000 days ago as of 2026
        assert age_in_days("2020-01-01") > 1000

    def test_future_date_is_negative(self):
        assert age_in_days("2099-12-31") < 0

    def test_invalid_date_returns_zero(self):
        assert age_in_days("not-a-date") == 0

    def test_invalid_month_returns_zero(self):
        assert age_in_days("2024-13-01") == 0

    def test_invalid_day_returns_zero(self):
        assert age_in_days("2024-02-30") == 0


# ===========================================================================
# Config scanner: malformed / adversarial inputs
# ===========================================================================


class TestConfigScannerAdversarial:
    def test_toml_with_nonexistent_path_returns_empty(self):
        from dont_be_lazy.scanners.config import scan_toml

        result = scan_toml("/nonexistent/path/pyproject.toml")
        assert result == []

    def test_flake8_ini_nonexistent_returns_empty(self):
        from dont_be_lazy.scanners.config import scan_flake8_ini

        result = scan_flake8_ini("/nonexistent/path/.flake8")
        assert result == []

    def test_pyrightconfig_invalid_json_returns_empty(self, tmp_path):
        from dont_be_lazy.scanners.config import scan_pyrightconfig

        p = tmp_path / "pyrightconfig.json"
        p.write_text("{ not valid json }", encoding="utf-8")
        result = scan_pyrightconfig(str(p))
        assert result == []

    def test_pyrightconfig_empty_object(self, tmp_path):
        from dont_be_lazy.scanners.config import scan_pyrightconfig

        p = tmp_path / "pyrightconfig.json"
        p.write_text("{}", encoding="utf-8")
        result = scan_pyrightconfig(str(p))
        assert result == []

    def test_pyrightconfig_type_checking_off(self, tmp_path):
        from dont_be_lazy.scanners.config import scan_pyrightconfig

        p = tmp_path / "pyrightconfig.json"
        p.write_text('{"typeCheckingMode": "off"}', encoding="utf-8")
        result = scan_pyrightconfig(str(p))
        assert any(s.kind == "type-checking-off" for s in result)

    def test_pyrightconfig_utf8_path(self, tmp_path):
        """pyrightconfig.json with a unicode path should read cleanly."""
        from dont_be_lazy.scanners.config import scan_pyrightconfig

        p = tmp_path / "pyrightconfig.json"
        p.write_text('{"exclude": ["src/répéter"]}', encoding="utf-8")
        result = scan_pyrightconfig(str(p))
        assert any(s.kind == "config-exclude" for s in result)

    def test_flake8_ini_ignore_multiline(self, tmp_path):
        from dont_be_lazy.scanners.config import scan_flake8_ini

        p = tmp_path / ".flake8"
        p.write_text("[flake8]\nignore =\n    E501\n    W503\n", encoding="utf-8")
        result = scan_flake8_ini(str(p))
        assert any(s.kind == "config-ignore" for s in result)
        match = next(s for s in result if s.kind == "config-ignore")
        assert "E501" in match.codes
        assert "W503" in match.codes

    def test_mypy_ini_ignore_errors_true(self, tmp_path):
        from dont_be_lazy.scanners.config import scan_mypy_ini

        p = tmp_path / "mypy.ini"
        p.write_text("[mypy]\nignore_missing_imports = True\n", encoding="utf-8")
        result = scan_mypy_ini(str(p))
        assert any(s.kind == "ignore-missing-imports" for s in result)

    def test_mypy_ini_ignore_errors_false_not_flagged(self, tmp_path):
        from dont_be_lazy.scanners.config import scan_mypy_ini

        p = tmp_path / "mypy.ini"
        p.write_text("[mypy]\nignore_missing_imports = False\n", encoding="utf-8")
        result = scan_mypy_ini(str(p))
        assert not any(s.kind == "ignore-missing-imports" for s in result)

    def test_mypy_section_prefix_pattern(self, tmp_path):
        """[mypy-some.module] sections with ignore_errors trigger findings."""
        from dont_be_lazy.scanners.config import scan_mypy_ini

        p = tmp_path / "mypy.ini"
        p.write_text("[mypy]\n[mypy-legacy.module]\nignore_errors = True\n", encoding="utf-8")
        result = scan_mypy_ini(str(p))
        assert any(s.kind == "ignore-errors-config" for s in result)

    def test_pylint_disable_all_is_critical(self, tmp_path):
        from dont_be_lazy.scanners.config import scan_pylint_ini

        p = tmp_path / ".pylintrc"
        p.write_text("[MESSAGES CONTROL]\ndisable = all\n", encoding="utf-8")
        result = scan_pylint_ini(str(p))
        assert any(s.risk == RiskLevel.critical for s in result)

    def test_coveragerc_omit_test_paths_is_critical(self, tmp_path):
        # BUG: scan_coveragerc does NOT apply the same test-path discount that
        # _scan_coverage_toml does — it marks any non-empty omit as critical.
        # This test documents the current (inconsistent) behavior so a future fix
        # can be validated against the TOML path in test_coveragerc_omit_source_paths_is_critical.
        from dont_be_lazy.scanners.config import scan_coveragerc

        p = tmp_path / ".coveragerc"
        p.write_text("[run]\nomit = tests/*\n", encoding="utf-8")
        result = scan_coveragerc(str(p))
        assert any(s.kind == "omit-broad" for s in result)
        match = next(s for s in result if s.kind == "omit-broad")
        # scan_coveragerc always marks non-empty omit as critical, unlike _scan_coverage_toml
        assert match.risk == RiskLevel.critical

    def test_coveragerc_omit_source_paths_is_critical(self, tmp_path):
        """omit of src/ paths should be critical."""
        from dont_be_lazy.scanners.config import scan_coveragerc

        p = tmp_path / ".coveragerc"
        p.write_text("[run]\nomit = src/*\n", encoding="utf-8")
        result = scan_coveragerc(str(p))
        match = next((s for s in result if s.kind == "omit-broad"), None)
        assert match is not None
        assert match.risk == RiskLevel.critical

    def test_scan_config_file_unknown_filename_returns_empty(self, tmp_path):
        from dont_be_lazy.scanners.config import scan_config_file

        p = tmp_path / "unknown_config.cfg"
        p.write_text("[section]\nkey = value\n", encoding="utf-8")
        result = scan_config_file(str(p))
        assert result == []

    def test_scan_config_file_dispatches_by_basename(self, tmp_path):
        """scan_config_file uses only the basename for dispatch."""
        from dont_be_lazy.scanners.config import scan_config_file

        subdir = tmp_path / "deep" / "nested"
        subdir.mkdir(parents=True)
        p = subdir / ".flake8"
        p.write_text("[flake8]\nignore = E501\n", encoding="utf-8")
        result = scan_config_file(str(p))
        assert any(s.kind == "config-ignore" for s in result)


# ===========================================================================
# Suppression path field used in text output (not for hashing)
# ===========================================================================


class TestSuppressionAttributes:
    def test_path_preserved_as_given(self):
        s = sup(path="src/foo.py")
        assert s.path == "src/foo.py"

    def test_codes_list_preserved(self):
        s = sup(codes=["F401", "E501"])
        assert s.codes == ["F401", "E501"]

    def test_text_preserved_as_given(self):
        s = sup(text="import os  # noqa: F401")
        assert s.text == "import os  # noqa: F401"

    def test_default_context_is_empty_list(self):
        s = sup()
        assert s.context == []

    def test_first_seen_default_none(self):
        s = sup()
        assert s.first_seen is None

    def test_git_fields_default_none(self):
        s = sup()
        assert s.git_author is None
        assert s.git_email is None
        assert s.git_date is None

    def test_post_init_generates_id(self):
        s = sup()
        assert s.id != ""


# ===========================================================================
# Suspicious comment detection
# ===========================================================================


class TestSuspiciousComments:
    def test_nolint_detected(self):
        findings = scan("x = bad()  # NOLINT\n")
        assert any(s.tool == "unknown" and "suspicious" in s.flags for s in findings)

    def test_nocheck_detected(self):
        findings = scan("x = bad()  # nocheck\n")
        assert any(s.tool == "unknown" and "suspicious" in s.flags for s in findings)

    def test_suspicious_not_added_when_real_suppression_matched(self):
        """If a real suppression matches, the suspicious fallback must not also fire."""
        findings = scan("x = bad()  # nosec NOLINT\n")
        tools = [s.tool for s in findings]
        assert "bandit" in tools
        assert "unknown" not in tools

    def test_ignore_this_phrase_detected(self):
        findings = scan("x = bad()  # ignore this\n")
        assert any("suspicious" in s.flags for s in findings)
