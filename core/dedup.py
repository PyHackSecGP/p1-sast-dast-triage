"""Deduplication engine — removes duplicate findings across scanners."""
from __future__ import annotations

from parsers.base import Finding


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Return deduplicated findings, preferring higher-severity duplicates.

    Two findings are duplicates if they share the same rule_id, file_path,
    and line_number (the components of Finding.id). When duplicates exist,
    the one with the higher severity rank is kept.
    """
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.id not in seen or f.severity_rank < seen[f.id].severity_rank:
            seen[f.id] = f
    return list(seen.values())
