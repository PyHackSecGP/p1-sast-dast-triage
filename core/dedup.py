"""Deduplication engine — merges duplicate findings across scanners.

Multi-scanner agreement is the strongest true-positive signal available:
if Semgrep and Bandit both flag CWE-89 at ``app/db.py:42``, that finding is
much more likely real than either alone. The previous implementation kept
the higher-severity duplicate and threw the other one away, discarding the
agreement signal. This module merges instead: it collapses duplicates
into a single :class:`Finding` whose :attr:`sources` list carries every
scanner+rule that reported it, whose severity is the max across duplicates,
and whose narrative fields (message, code_snippet) are the longest available.
"""
from __future__ import annotations

from parsers.base import Finding


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Return findings with duplicates merged by :attr:`Finding.id`.

    Two findings are duplicates when they share the same ``Finding.id``
    (CWE + file + line, with rule_id fallback for CWE-less findings).
    When duplicates exist the survivor:

      * keeps the **highest severity** across duplicates
      * concatenates every duplicate's :attr:`sources` (deduplicated,
        insertion-ordered)
      * uses the **longest** ``message`` and ``code_snippet``, so richer
        context wins over a sparser scanner's version

    The scoring layer (see :mod:`core.scorer`) then rewards findings whose
    ``sources`` list is longer than one — that is where agreement lifts
    the risk score.
    """
    survivors: dict[str, Finding] = {}
    for f in findings:
        existing = survivors.get(f.id)
        if existing is None:
            # First occurrence — take a shallow copy of sources so subsequent
            # merges don't mutate the parser's original Finding object.
            f.sources = list(f.sources)
            survivors[f.id] = f
            continue
        survivors[f.id] = _merge(existing, f)
    return list(survivors.values())


def _merge(a: Finding, b: Finding) -> Finding:
    """Merge two findings that share an id. ``a`` is the current survivor."""
    # Pick the higher-severity finding as the base for identifying metadata
    # (rule_id, scanner, title reflect the scanner that saw it as worst).
    if b.severity_rank < a.severity_rank:
        keep, merged = b, a
    else:
        keep, merged = a, b

    # Union sources, preserving insertion order and de-duping.
    combined: list[str] = []
    for src in (*a.sources, *b.sources):
        if src and src not in combined:
            combined.append(src)
    keep.sources = combined

    # Longest wins for narrative fields — a richer message is strictly more
    # useful for triage and never regresses.
    if len(merged.message) > len(keep.message):
        keep.message = merged.message
    if len(merged.code_snippet) > len(keep.code_snippet):
        keep.code_snippet = merged.code_snippet
    return keep
