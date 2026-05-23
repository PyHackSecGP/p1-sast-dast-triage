"""Base finding schema and abstract parser interface."""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


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
    cvss_score: float = 0.0
    code_snippet: str = ""
    url: str = ""          # for ZAP web findings
    cwe: str = ""
    tags: list[str] = field(default_factory=list)
    false_positive: bool | None = None   # None = unreviewed
    fp_reason: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Stable hash used for deduplication across scanners."""
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

    def _normalize_severity(self, raw: str) -> str:
        """Map scanner-specific severity strings to canonical levels."""
        mapping = {
            "critical": "critical", "high": "high", "medium": "medium",
            "low": "low", "info": "info", "informational": "info",
            "warning": "medium", "error": "high",
            # zap risk codes
            "3": "high", "2": "medium", "1": "low", "0": "info",
        }
        return mapping.get(raw.strip().lower(), mapping.get(raw.strip(), "info"))
