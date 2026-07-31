from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from .models import Evidence


def _ev(
    key: str,
    value: Any,
    source: str,
    source_class: str = "device_read",
    *,
    confidence: float = 1.0,
    excerpt: str = "",
    observed: bool = True,
    metadata: Mapping[str, Any] | None = None,
) -> Evidence:
    return Evidence(
        key=key,
        value=str(value).strip(),
        source=source,
        source_class=source_class,
        observed=observed,
        confidence=max(0.0, min(1.0, confidence)),
        excerpt=excerpt.strip(),
        metadata=dict(metadata or {}),
    )


def _first_value(evidence: Sequence[Evidence], key: str) -> str | None:
    for item in evidence:
        if item.key == key and item.value:
            return item.value
    return None


def _values(evidence: Sequence[Evidence], key: str) -> list[str]:
    seen: list[str] = []
    for item in evidence:
        if item.key == key and item.value not in seen:
            seen.append(item.value)
    return seen


def _has_value(evidence: Sequence[Evidence], key: str, value: str | None = None) -> bool:
    for item in evidence:
        if item.key != key:
            continue
        if value is None or item.value.casefold() == value.casefold():
            return True
    return False


def _line_match(pattern: str, text: str, flags: int = re.IGNORECASE | re.MULTILINE) -> re.Match[str] | None:
    return re.search(pattern, text, flags)


def _extract_kv(text: str, label: str) -> tuple[str, str] | None:
    match = _line_match(rf"^\s*{re.escape(label)}\s*:\s*(.*?)\s*$", text)
    if not match:
        return None
    return match.group(1), match.group(0)
