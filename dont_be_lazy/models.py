"""Core data model for dont_be_lazy suppressions."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @staticmethod
    def _idx(v: RiskLevel) -> int:
        return [RiskLevel.low, RiskLevel.medium, RiskLevel.high, RiskLevel.critical].index(v)

    def __lt__(self, other: RiskLevel) -> bool:
        return self._idx(self) < self._idx(other)

    def __le__(self, other: RiskLevel) -> bool:
        return self._idx(self) <= self._idx(other)

    def __gt__(self, other: RiskLevel) -> bool:
        return self._idx(self) > self._idx(other)

    def __ge__(self, other: RiskLevel) -> bool:
        return self._idx(self) >= self._idx(other)


class ScopeKind(str, Enum):
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
