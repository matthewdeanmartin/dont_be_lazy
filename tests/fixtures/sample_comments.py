"""Sample file with suppression comments for testing."""

thing = "wrong"


class _MissingAttr:
    pass


other = _MissingAttr()
debug = True
impossible = False


def bad() -> int:
    return 1


def worse() -> int:
    return 2


x = 1
y = 2
z = 3

a = "not a suppression noqa"
b = """
type: ignore should not be flagged here
"""

# ruff: noqa
c: int = thing  # type: ignore
d = other.missing  # type: ignore[attr-defined]

e = bad()  # nosec
f = worse()  # nosec B602

if debug:  # pragma: no cover
    pass

if impossible:  # pragma: no branch
    pass

g = 1  # pylint: disable=invalid-name
h = 2  # pylint: disable=all
i = 3  # pyright: ignore
j = 4  # pyright: ignore[reportUnknownMemberType]

# fmt: off
k = [1,2,3]
# fmt: on

m = 5  # fmt: skip


# isort: skip_file
