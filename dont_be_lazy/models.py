"""Core data model for dont_be_lazy suppressions."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum

# pylint: disable=invalid-name


class RiskLevel(str, Enum):
    """Severity assigned to a suppression."""

    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @staticmethod
    def idx(v: RiskLevel) -> int:
        """Return the integer index of a RiskLevel for comparison."""
        return [RiskLevel.low, RiskLevel.medium, RiskLevel.high, RiskLevel.critical].index(v)

    @classmethod
    def coerce(cls, other: str) -> RiskLevel:
        """Coerce a string into a RiskLevel instance."""
        return other if isinstance(other, cls) else cls(other)

    def __lt__(self, other: str) -> bool:
        return self.idx(self) < self.idx(self.coerce(other))

    def __le__(self, other: str) -> bool:
        return self.idx(self) <= self.idx(self.coerce(other))

    def __gt__(self, other: str) -> bool:
        return self.idx(self) > self.idx(self.coerce(other))

    def __ge__(self, other: str) -> bool:
        return self.idx(self) >= self.idx(self.coerce(other))


class ScopeKind(str, Enum):
    """Scope at which a suppression applies."""

    line = "line"
    next_line = "next-line"
    block = "block"
    file = "file"
    module = "module"
    config = "config"
    path = "path"
    test = "test"
    unknown = "unknown"


@dataclass
class Suppression:
    """Normalized representation of a detected suppression."""

    tool: str
    kind: str
    pattern: str
    path: str
    line: int
    text: str
    end_line: int | None = None
    scope: ScopeKind = ScopeKind.line
    codes: list[str] = field(default_factory=list)
    reason: str | None = None
    risk: RiskLevel = RiskLevel.medium
    flags: list[str] = field(default_factory=list)
    id: str = field(default="", init=False)
    first_seen: str | None = None
    git_author: str | None = None
    git_email: str | None = None
    git_date: str | None = None
    owner: str | None = None
    context: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.id = self.make_id()

    def normalized_path(self) -> str:
        """Return a normalized, forward-slash version of the file path."""
        return os.path.normpath(self.path).replace("\\", "/")

    def normalized_text(self) -> str:
        """Return normalized text with collapsed whitespace."""
        return " ".join(self.text.strip().split())

    def nearby_source_hash(self) -> str:
        """Generate a hash of the nearby source text."""
        return hashlib.sha256(self.normalized_text().encode()).hexdigest()[:12]

    def fingerprint_raw(self) -> str:
        """Generate the raw string used for fingerprinting."""
        return (
            f"{self.normalized_path()}|{self.kind}|{','.join(sorted(self.codes))}|"
            f"{self.nearby_source_hash()}|{self.normalized_text()}"
        )

    def make_id(self) -> str:
        """Generate a short, stable ID for the suppression."""
        raw = self.fingerprint_raw()
        digest = hashlib.sha256(raw.encode()).hexdigest()[:8].upper()
        return f"DBL{digest}"

    def fingerprint(self) -> str:
        """Stable fingerprint for baseline comparison."""
        raw = self.fingerprint_raw()
        return hashlib.sha256(raw.encode()).hexdigest()
