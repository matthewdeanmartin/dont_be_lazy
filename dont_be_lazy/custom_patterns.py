"""Custom suppression pattern support loaded from config."""

from __future__ import annotations

import io
import re
import tokenize
from typing import Any

from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression


class CustomPatternScanner:
    """Scans for user-defined suppression patterns from config."""

    def __init__(self, patterns_config: dict[str, Any]) -> None:
        self.compiled: list[tuple[str, ScopeKind, RiskLevel, re.Pattern[str]]] = []
        for tool_name, entry in patterns_config.items():
            if isinstance(entry, dict):
                raw_patterns = entry.get("patterns", [])
                scope_str = entry.get("scope", "line")
                risk_str = entry.get("risk", "medium")
            elif isinstance(entry, list):
                raw_patterns = entry
                scope_str = "line"
                risk_str = "medium"
            else:
                continue

            scope = ScopeKind(scope_str) if scope_str in ScopeKind._value2member_map_ else ScopeKind.line
            try:
                risk = RiskLevel(risk_str)
            except ValueError:
                risk = RiskLevel.medium

            for raw in raw_patterns:
                try:
                    compiled = re.compile(raw)
                    self.compiled.append((tool_name, scope, risk, compiled))
                except re.error:
                    pass  # Invalid regex — skip silently

    def scan(self, path: str, source: str) -> list[Suppression]:
        """Scan source comments for configured custom suppression patterns."""
        if not self.compiled:
            return []

        results: list[Suppression] = []
        source_lines = source.splitlines()

        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
        except tokenize.TokenError:
            return results

        for tok_type, tok_string, tok_start, _, _ in tokens:
            if tok_type != tokenize.COMMENT:
                continue
            line_no = tok_start[0]
            src_line = source_lines[line_no - 1] if line_no <= len(source_lines) else ""

            for tool_name, scope, risk, pattern in self.compiled:
                m = pattern.search(tok_string)
                if not m:
                    continue
                groups = m.groupdict()
                codes_raw = groups.get("codes", "") or ""
                codes = [c.strip() for c in codes_raw.replace(",", " ").split() if c.strip()]
                reason = groups.get("reason") or None
                results.append(
                    Suppression(
                        tool=tool_name,
                        kind="custom",
                        pattern=pattern.pattern,
                        path=path,
                        line=line_no,
                        end_line=line_no,
                        scope=scope,
                        codes=codes,
                        reason=reason,
                        risk=risk,
                        flags=["custom-pattern"],
                        text=src_line,
                    )
                )

        return results
