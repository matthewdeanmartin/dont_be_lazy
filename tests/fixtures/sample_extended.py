"""Sample file for extended suppression types."""

# pytype: disable=attribute-error
x = something.bad
# pytype: enable=attribute-error

y = thing  # ty: ignore
z = other  # ty: ignore[rule-name]

a = dangerous()  # nosemgrep
b = maybe()  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use

password = "hunter2"  # pragma: allowlist secret
secret = "abc"  # pragma: whitelist secret

# autopep8: off
ugly = [1, 2, 3]
# autopep8: on

# yapf: disable
messy = {1:2,3:4}
# yapf: enable

x = 1  # NOSONAR

# ignore this workaround

from hypothesis import HealthCheck, settings


@settings(suppress_health_check=[HealthCheck.too_slow])
def test_hypothesis_health():
    pass


@settings(deadline=None)
def test_hypothesis_deadline():
    pass
