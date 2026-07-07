"""Base finding schema and abstract parser interface."""
from __future__ import annotations

import hashlib
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

_log = logging.getLogger(__name__)


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_CWE_RE = re.compile(r"(?:CWE[-_]?)?(\d{1,5})", re.IGNORECASE)


def normalize_cwe(raw: object) -> str:
    """Canonicalize any scanner's CWE identifier to ``CWE-<number>``.

    Accepts:
        ``"CWE-89: Improper Neutralization of Special Elements..."``
        ``"CWE-89"``, ``"cwe_89"``, ``"89"``, ``89``
        ``{"id": 89, "link": "..."}`` (Bandit >=1.7.3)
        ``["CWE-89", "CWE-564"]``  (Semgrep/Trivy/Nuclei list form)

    Returns ``""`` when no CWE number can be extracted. The output form is
    stable across scanners so ``Finding.id`` collapses cross-scanner duplicates
    for the same weakness at the same location.
    """
    if raw is None or raw == "":
        return ""
    if isinstance(raw, list):
        for item in raw:
            result = normalize_cwe(item)
            if result:
                return result
        return ""
    if isinstance(raw, dict):
        return normalize_cwe(raw.get("id", ""))
    match = _CWE_RE.search(str(raw))
    if not match:
        return ""
    return f"CWE-{int(match.group(1))}"


@dataclass
class Finding:
    """Normalized security finding from any supported scanner."""

    scanner: str
    rule_id: str
    title: str
    severity: str          # critical | high | medium | low | info
    message: str
    file_path: str
    line_number: int
    # CWE-based heuristic score (0-10). NOT a computed CVSS vector.
    risk_score: float = 0.0
    code_snippet: str = ""
    url: str = ""          # for ZAP web findings
    cwe: str = ""
    tags: list[str] = field(default_factory=list)
    false_positive: bool | None = None   # None = unreviewed
    fp_reason: str = ""
    # LLM triage status: confirmed | likely_fp | unreviewed | suppressed
    status: str = "confirmed"
    # Cross-scanner agreement trail. Seeded per parser to ``["<scanner>:<rule_id>"]``.
    # Dedup merges every duplicate scanner's entry in here so the report keeps
    # the strongest true-positive signal we have.
    sources: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Seed sources so callers that build a Finding directly (parsers,
        # tests) get a sensible default without having to duplicate the
        # scanner+rule_id combination themselves.
        if not self.sources and self.scanner and self.rule_id:
            self.sources = [f"{self.scanner}:{self.rule_id}"]

    @property
    def id(self) -> str:
        """Stable hash for cross-scanner deduplication.

        Uses CWE + location when available so Semgrep and Bandit findings
        for the same vulnerability (e.g. CWE-89 at app.py:42) collapse to
        one entry. Falls back to rule_id + location for scanners without CWE.
        """
        if self.cwe:
            key = f"{self.cwe}:{self.file_path}:{self.line_number}"
        else:
            key = f"{self.rule_id}:{self.file_path}:{self.line_number}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 99)


class BaseParser(ABC):
    """Abstract base for all scanner output parsers."""

    @abstractmethod
    def parse(self, path: str) -> list[Finding]:
        """Parse scanner output file and return normalized findings."""
        ...

    #: Canonical severity levels, ranked. Every parser must produce one of these.
    CANONICAL_SEVERITIES = ("critical", "high", "medium", "low", "info")

    #: One central mapping table for every scanner's severity strings.
    #: Keys are lowercased. Values are one of ``CANONICAL_SEVERITIES``.
    #:
    #: Mapping per scanner:
    #:   - Semgrep: ``ERROR→high``, ``WARNING→medium``, ``INFO→info``. Metadata
    #:     ``impact``+``confidence`` may lift ``WARNING`` to ``critical`` in the
    #:     Semgrep parser after the base call — that upgrade is intentional and
    #:     is applied outside this table.
    #:   - Bandit:  ``HIGH/MEDIUM/LOW → high/medium/low``.
    #:   - ZAP:     ``riskcode 3→high, 2→medium, 1→low, 0→info``.
    #:   - Trivy:   ``CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN → critical/high/medium/low/info``.
    #:   - Nuclei:  ``critical/high/medium/low/info`` pass-through, ``unknown→info``.
    SEVERITY_MAP: ClassVar[dict[str, str]] = {
        # Canonical passthrough
        "critical":     "critical",
        "high":         "high",
        "medium":       "medium",
        "low":          "low",
        "info":         "info",
        "informational": "info",
        # Semgrep
        "error":        "high",
        "warning":      "medium",
        # Trivy / Nuclei
        "unknown":      "info",
        # ZAP riskcode
        "3":            "high",
        "2":            "medium",
        "1":            "low",
        "0":            "info",
    }

    def _normalize_severity(self, raw: str | int) -> str:
        """Map any scanner's severity token to one of ``CANONICAL_SEVERITIES``.

        Unknown tokens map to ``info`` and log a warning — the parser must
        never crash on an unfamiliar severity string.
        """
        token = str(raw).strip().lower()
        mapped = self.SEVERITY_MAP.get(token)
        if mapped is None:
            _log.warning(
                "%s: unknown severity token %r, defaulting to 'info'",
                type(self).__name__, raw,
            )
            return "info"
        return mapped
