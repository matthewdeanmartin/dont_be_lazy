
import pytest
from dont_be_lazy.models import Suppression, RiskLevel, ScopeKind

@pytest.fixture
def sample_findings():
    return [
        Suppression(
            tool="ruff", kind="noqa-blanket", pattern="# noqa", path="src/a.py", line=10, end_line=10,
            scope=ScopeKind.line, codes=[], reason=None, risk=RiskLevel.high, flags=["blanket-ignore"], text="# noqa"
        ),
        Suppression(
            tool="pytest", kind="skip-with-reason", pattern="skip-with-reason", path="tests/test_b.py", line=5, end_line=5,
            scope=ScopeKind.test, codes=[], reason="flaky", risk=RiskLevel.medium, flags=[], text="@pytest.mark.skip(reason='flaky')"
        ),
        Suppression(
            tool="bandit", kind="nosec-blanket", pattern="# nosec", path="src/b.py", line=20, end_line=20,
            scope=ScopeKind.line, codes=[], reason=None, risk=RiskLevel.critical, flags=["blanket-ignore"], text="# nosec"
        )
    ]
