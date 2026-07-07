"""Severity normalization — canonical five-level output for every scanner token."""
from __future__ import annotations

import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers.base import BaseParser


class _Concrete(BaseParser):
    """Minimal concrete BaseParser so we can call _normalize_severity."""

    def parse(self, path: str) -> list:  # pragma: no cover - not used
        return []


@pytest.fixture
def parser() -> _Concrete:
    return _Concrete()


@pytest.mark.parametrize(
    "raw,expected",
    [
        # Canonical passthrough
        ("critical", "critical"),
        ("high",     "high"),
        ("medium",   "medium"),
        ("low",      "low"),
        ("info",     "info"),
        ("informational", "info"),
        # Case-insensitive
        ("CRITICAL", "critical"),
        ("High",     "high"),
        # Whitespace tolerance
        (" high ",   "high"),
        # Semgrep
        ("error",    "high"),
        ("ERROR",    "high"),
        ("warning",  "medium"),
        ("WARNING",  "medium"),
        # Trivy / Nuclei
        ("unknown",  "info"),
        ("UNKNOWN",  "info"),
        # ZAP riskcode (both str and int)
        ("3", "high"),
        ("2", "medium"),
        ("1", "low"),
        ("0", "info"),
        (3,   "high"),
        (2,   "medium"),
        (1,   "low"),
        (0,   "info"),
    ],
)
def test_every_documented_token_maps_to_canonical(
    parser: _Concrete, raw: object, expected: str
) -> None:
    result = parser._normalize_severity(raw)  # type: ignore[arg-type]
    assert result == expected
    assert result in BaseParser.CANONICAL_SEVERITIES


def test_unknown_token_defaults_to_info(parser: _Concrete) -> None:
    assert parser._normalize_severity("apocalyptic") == "info"


def test_unknown_token_logs_warning(
    parser: _Concrete, caplog: pytest.LogCaptureFixture
) -> None:
    """Unknown severities must never crash — they log and default to info."""
    with caplog.at_level(logging.WARNING, logger="parsers.base"):
        result = parser._normalize_severity("cataclysmic")
    assert result == "info"
    assert any("cataclysmic" in rec.message for rec in caplog.records), (
        "Expected a warning log for the unknown severity token"
    )


def test_empty_string_defaults_to_info(parser: _Concrete) -> None:
    """Missing severity fields (empty string) fall back cleanly."""
    assert parser._normalize_severity("") == "info"


def test_canonical_set_matches_severity_order() -> None:
    """The rank map must cover every canonical severity — otherwise sorting
    and 'fail-on' comparisons produce silently wrong results."""
    from parsers.base import SEVERITY_ORDER
    assert set(BaseParser.CANONICAL_SEVERITIES) == set(SEVERITY_ORDER.keys())
