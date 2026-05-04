"""Reason extraction and quality classification."""

from __future__ import annotations

import re

_PLACEHOLDER = re.compile(
    r"\b(todo|fixme|fix\s+later|temporary|temp|legacy|hack|workaround|remove\s+later|pending)\b",
    re.IGNORECASE,
)
_ISSUE_LINK = re.compile(
    r"(https?://\S+|#\d+|\b[A-Z]+-\d+\b)",
)
_EXPIRY = re.compile(
    r"\b(expires?|until|remove[- ]after)\s*:?\s*(\d{4}-\d{2}-\d{2})",
    re.IGNORECASE,
)


def classify_reason(reason: str | None) -> tuple[str | None, str]:
    """Return (reason, quality) where quality is one of none/placeholder/plain-text/issue-link/expiry."""
    if not reason or not reason.strip():
        return None, "none"
    r = reason.strip()
    if _EXPIRY.search(r):
        return r, "expiry"
    if _ISSUE_LINK.search(r):
        return r, "issue-link"
    if _PLACEHOLDER.search(r):
        return r, "placeholder"
    return r, "plain-text"


def extract_trailing_reason(comment_text: str, suppression_token_end: int) -> str | None:
    """Pull the text after the suppression token as a reason, if present."""
    tail = comment_text[suppression_token_end:].strip().lstrip("#").strip()
    return tail if tail else None
