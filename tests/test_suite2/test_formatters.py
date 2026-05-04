
import pytest
from dont_be_lazy.models import Suppression, RiskLevel, ScopeKind
from dont_be_lazy.formatters.json_fmt import format_json
from dont_be_lazy.formatters.markdown_fmt import format_markdown
from dont_be_lazy.formatters.table import format_table

def test_format_json(sample_findings):
    out = format_json(sample_findings)
    assert '"tool": "ruff"' in out
    assert '"tool": "pytest"' in out
    assert '"reason": "flaky"' in out
    assert '"tool": "bandit"' in out

def test_format_markdown(sample_findings):
    out = format_markdown(sample_findings)
    assert "| Tool | Count | High | Critical | No reason |" in out
    assert "| ruff | 1 | 1 | 0 | 1 |" in out
    assert "| pytest | 1 | 0 | 0 | 0 |" in out
    assert "| bandit | 1 | 1 | 1 | 1 |" in out

def test_format_table(sample_findings):
    # Pass no_color=True to simplify matching
    out = format_table(sample_findings, no_color=True)
    assert "ruff" in out
    assert "pytest" in out
    assert "src/a.py" in out
    assert "tests/test_b.py" in out
