"""Tests for parsers.base.normalize_cwe — the cross-scanner CWE canonicalizer."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers.base import Finding, normalize_cwe


@pytest.mark.parametrize(
    "raw,expected",
    [
        # Bare number in various types
        (89, "CWE-89"),
        ("89", "CWE-89"),
        # Standard prefixed
        ("CWE-89", "CWE-89"),
        ("cwe-89", "CWE-89"),
        ("CWE_89", "CWE-89"),
        # Semgrep-style prefixed with description
        ("CWE-89: Improper Neutralization of Special Elements used in an SQL Command", "CWE-89"),
        # Bandit-style dict
        ({"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"}, "CWE-89"),
        ({"id": "CWE-89"}, "CWE-89"),
        # List form (Semgrep/Trivy/Nuclei)
        (["CWE-89"], "CWE-89"),
        (["CWE-89", "CWE-564"], "CWE-89"),
        (["89"], "CWE-89"),
        # Empty inputs
        ("", ""),
        (None, ""),
        ([], ""),
        ({}, ""),
        # Non-extractable
        ("no cwe here", ""),
        ("garbage", ""),
        # High-numbered CWE
        ("CWE-1333", "CWE-1333"),
    ],
)
def test_normalize_cwe(raw: object, expected: str) -> None:
    assert normalize_cwe(raw) == expected


def test_cross_scanner_dedup_key_matches() -> None:
    """Semgrep + Bandit findings for the same CWE:file:line collapse via Finding.id."""
    # Semgrep-style raw CWE
    semgrep = Finding(
        scanner="semgrep",
        rule_id="python.django.security.injection.sql.sql-injection-string-concat",
        title="sql-injection",
        severity="high",
        message="SQLi",
        file_path="app/db.py",
        line_number=42,
        cwe=normalize_cwe(
            ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]
        ),
    )
    # Bandit-style raw CWE (dict with int id)
    bandit = Finding(
        scanner="bandit",
        rule_id="B608",
        title="hardcoded_sql_expressions",
        severity="high",
        message="SQLi",
        file_path="app/db.py",
        line_number=42,
        cwe=normalize_cwe({"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"}),
    )
    # Trivy-style raw CWE (bare list of "CWE-N")
    trivy = Finding(
        scanner="trivy",
        rule_id="ADR-0001",
        title="cve-adjacent",
        severity="high",
        message="SQLi",
        file_path="app/db.py",
        line_number=42,
        cwe=normalize_cwe(["CWE-89"]),
    )
    # ZAP-style raw CWE (bare number string)
    zap = Finding(
        scanner="zap",
        rule_id="40018",
        title="sql-injection",
        severity="high",
        message="SQLi",
        file_path="app/db.py",
        line_number=42,
        cwe=normalize_cwe("89"),
    )

    ids = {semgrep.id, bandit.id, trivy.id, zap.id}
    assert semgrep.cwe == bandit.cwe == trivy.cwe == zap.cwe == "CWE-89"
    assert len(ids) == 1, f"Expected identical dedup key across 4 scanners, got: {ids}"
