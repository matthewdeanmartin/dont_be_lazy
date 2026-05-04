"""AST scanner for pytest/unittest skip/xfail decorators and calls."""

from __future__ import annotations

import ast

from dont_be_lazy.models import RiskLevel, ScopeKind, Suppression


def _static_str(node: ast.expr) -> str | None:
    """Return a static string value from an AST node, or None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _get_kwarg(keywords: list, name: str) -> ast.expr | None:
    for kw in keywords:
        if kw.arg == name:
            return kw.value
    return None


def _make(
    tool: str,
    kind: str,
    path: str,
    line: int,
    text: str,
    reason: str | None = None,
    risk: RiskLevel = RiskLevel.medium,
    flags: list[str] | None = None,
) -> Suppression:
    return Suppression(
        tool=tool,
        kind=kind,
        pattern=kind,
        path=path,
        line=line,
        end_line=line,
        scope=ScopeKind.test,
        codes=[],
        reason=reason,
        risk=risk,
        flags=flags or [],
        text=text,
    )


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, source_lines: list[str]) -> None:
        self.path = path
        self.source_lines = source_lines
        self.findings: list[Suppression] = []

    def _src(self, line: int) -> str:
        return self.source_lines[line - 1] if line <= len(self.source_lines) else ""

    def _visit_decorator(self, dec: ast.expr, func_line: int) -> None:
        line = getattr(dec, "lineno", func_line)
        src = self._src(line)

        # Resolve decorator name
        if isinstance(dec, ast.Attribute):
            name = f"{ast.unparse(dec)}" if hasattr(ast, "unparse") else ""
        elif isinstance(dec, ast.Call):
            name = ast.unparse(dec.func) if hasattr(ast, "unparse") else ""
        else:
            name = ast.unparse(dec) if hasattr(ast, "unparse") else ""

        # pytest.mark.skip / pytest.mark.skip(reason=...)
        if name in ("pytest.mark.skip", "mark.skip"):
            if isinstance(dec, ast.Call):
                reason_node = _get_kwarg(dec.keywords, "reason")
                if reason_node:
                    arg_nodes = dec.args
                    reason_val = _static_str(reason_node) or (_static_str(arg_nodes[0]) if arg_nodes else None)
                else:
                    reason_val = _static_str(dec.args[0]) if dec.args else None
                risk = RiskLevel.medium if reason_val else RiskLevel.high
                flags = [] if reason_val else ["no-reason"]
                self.findings.append(
                    _make(
                        "pytest",
                        "skip-with-reason" if reason_val else "skip-unconditional",
                        self.path,
                        line,
                        src,
                        reason=reason_val,
                        risk=risk,
                        flags=flags,
                    )
                )
            else:
                self.findings.append(
                    _make(
                        "pytest", "skip-unconditional", self.path, line, src, risk=RiskLevel.high, flags=["no-reason"]
                    )
                )

        # pytest.mark.skipif
        elif name in ("pytest.mark.skipif", "mark.skipif"):
            reason_val = None
            if isinstance(dec, ast.Call):
                reason_node = _get_kwarg(dec.keywords, "reason")
                reason_val = _static_str(reason_node) if reason_node else None
            risk = RiskLevel.low if reason_val else RiskLevel.medium
            self.findings.append(
                _make("pytest", "skipif-with-reason", self.path, line, src, reason=reason_val, risk=risk)
            )

        # pytest.mark.xfail
        elif name in ("pytest.mark.xfail", "mark.xfail"):
            reason_val = None
            strict = False
            if isinstance(dec, ast.Call):
                reason_node = _get_kwarg(dec.keywords, "reason")
                reason_val = _static_str(reason_node) if reason_node else None
                strict_node = _get_kwarg(dec.keywords, "strict")
                if isinstance(strict_node, ast.Constant):
                    strict = bool(strict_node.value)
            kind = "xfail-strict" if strict else "xfail-nonstrict"
            risk = RiskLevel.low if strict else RiskLevel.medium
            self.findings.append(_make("pytest", kind, self.path, line, src, reason=reason_val, risk=risk))

        # unittest.skip
        elif name in ("unittest.skip", "skip"):
            reason_val = None
            if isinstance(dec, ast.Call) and dec.args:
                reason_val = _static_str(dec.args[0])
            elif isinstance(dec, ast.Call):
                reason_node = _get_kwarg(dec.keywords, "reason")
                reason_val = _static_str(reason_node) if reason_node else None
            risk = RiskLevel.high if not reason_val else RiskLevel.medium
            self.findings.append(
                _make(
                    "unittest",
                    "skip-unconditional",
                    self.path,
                    line,
                    src,
                    reason=reason_val,
                    risk=risk,
                    flags=["no-reason"] if not reason_val else [],
                )
            )

        # unittest.skipIf / unittest.skipUnless
        elif name in ("unittest.skipIf", "unittest.skipUnless", "skipIf", "skipUnless"):
            reason_val = None
            if isinstance(dec, ast.Call) and len(dec.args) >= 2:
                reason_val = _static_str(dec.args[1])
            self.findings.append(
                _make("unittest", "skip-conditional", self.path, line, src, reason=reason_val, risk=RiskLevel.medium)
            )

        # hypothesis @settings(suppress_health_check=...) or deadline=None
        elif name in ("settings", "hypothesis.settings"):
            if isinstance(dec, ast.Call):
                shc = _get_kwarg(dec.keywords, "suppress_health_check")
                if shc is not None:
                    self.findings.append(
                        _make("hypothesis", "suppress-health-check", self.path, line, src, risk=RiskLevel.medium)
                    )
                deadline = _get_kwarg(dec.keywords, "deadline")
                if deadline is not None and isinstance(deadline, ast.Constant) and deadline.value is None:
                    self.findings.append(
                        _make("hypothesis", "deadline-none", self.path, line, src, risk=RiskLevel.medium)
                    )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for dec in node.decorator_list:
            self._visit_decorator(dec, node.lineno)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        for dec in node.decorator_list:
            self._visit_decorator(dec, node.lineno)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for dec in node.decorator_list:
            self._visit_decorator(dec, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect imperative pytest.skip / pytest.xfail / self.skipTest."""
        line = node.lineno
        src = self._src(line)
        func_name = ast.unparse(node.func) if hasattr(ast, "unparse") else ""

        if func_name in ("pytest.skip", "skip"):
            reason_val = _static_str(node.args[0]) if node.args else None
            if reason_val is None:
                reason_node = _get_kwarg(node.keywords, "reason")
                reason_val = _static_str(reason_node) if reason_node else None
            self.findings.append(
                _make("pytest", "skip-call", self.path, line, src, reason=reason_val, risk=RiskLevel.medium)
            )

        elif func_name in ("pytest.xfail", "xfail"):
            reason_val = _static_str(node.args[0]) if node.args else None
            self.findings.append(
                _make("pytest", "xfail-call", self.path, line, src, reason=reason_val, risk=RiskLevel.medium)
            )

        elif func_name in ("self.skipTest", "skipTest"):
            reason_val = _static_str(node.args[0]) if node.args else None
            self.findings.append(
                _make("unittest", "skip-test-call", self.path, line, src, reason=reason_val, risk=RiskLevel.medium)
            )

        elif func_name in ("unittest.SkipTest",) or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "SkipTest"
        ):
            reason_val = _static_str(node.args[0]) if node.args else None
            self.findings.append(
                _make("unittest", "raise-skip-test", self.path, line, src, reason=reason_val, risk=RiskLevel.medium)
            )

        self.generic_visit(node)


def scan_python_ast(path: str, source: str) -> list[Suppression]:
    """Scan a Python source file for test skip/xfail patterns via AST."""
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return []

    source_lines = source.splitlines()
    visitor = _Visitor(path, source_lines)
    visitor.visit(tree)
    return visitor.findings
