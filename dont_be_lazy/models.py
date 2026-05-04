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
    def _idx(v: RiskLevel) -> int:
        return [RiskLevel.low, RiskLevel.medium, RiskLevel.high, RiskLevel.critical].index(v)

    @classmethod
    def _coerce(cls, other: str) -> RiskLevel:
        return other if isinstance(other, cls) else cls(other)

    def __lt__(self, other: str) -> bool:
        return self._idx(self) < self._idx(self._coerce(other))

    def __le__(self, other: str) -> bool:
        return self._idx(self) <= self._idx(self._coerce(other))

    def __gt__(self, other: str) -> bool:
        return self._idx(self) > self._idx(self._coerce(other))

    def __ge__(self, other: str) -> bool:
        return self._idx(self) >= self._idx(self._coerce(other))


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
    end_line: int | None
    scope: ScopeKind
    codes: list[str]
    reason: str | None
    risk: RiskLevel
    flags: list[str]
    text: str
    id: str = field(default="", init=False)
    first_seen: str | None = None
    git_author: str | None = None
    git_email: str | None = None
    git_date: str | None = None
    owner: str | None = None
    context: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.id = self._make_id()

    def _normalized_path(self) -> str:
        return os.path.normpath(self.path).replace("\\", "/")

    def _normalized_text(self) -> str:
        return " ".join(self.text.strip().split())

    def _nearby_source_hash(self) -> str:
        return hashlib.sha256(self._normalized_text().encode()).hexdigest()[:12]

    def _fingerprint_raw(self) -> str:
        return (
            f"{self._normalized_path()}|{self.kind}|{','.join(sorted(self.codes))}|"
            f"{self._nearby_source_hash()}|{self._normalized_text()}"
        )

    def _make_id(self) -> str:
        raw = self._fingerprint_raw()
        digest = hashlib.sha256(raw.encode()).hexdigest()[:8].upper()
        return f"DBL{digest}"

    def fingerprint(self) -> str:
        """Stable fingerprint for baseline comparison."""
        raw = self._fingerprint_raw()
        return hashlib.sha256(raw.encode()).hexdigest()
