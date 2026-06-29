"""Tests for deduplication and risk scoring."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers import SemgrepParser, BanditParser
from core.dedup import deduplicate
from core.scorer import assign_risk_score

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_dedup_same_scanner():
    """Duplicate findings from same scanner are collapsed."""
    findings = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    duped = findings + findings
    result = deduplicate(duped)
    assert len(result) == len(findings)
    print(f"  dedup same-scanner: {len(duped)} → {len(result)} OK")


def test_dedup_cross_scanner():
    """CWE-based dedup collapses same vuln reported by two scanners."""
    semgrep = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    bandit = BanditParser().parse(f"{FIXTURES}/bandit_sample.json")
    # Semgrep and Bandit both flag CWE-89 at app/db.py:42 — dedup collapses to one.
    combined = semgrep + bandit
    result = deduplicate(combined)
    assert len(result) == len(combined) - 1, (
        f"Expected {len(combined) - 1} findings after cross-scanner dedup, got {len(result)}"
    )
    print(f"  dedup cross-scanner: {len(combined)} → {len(result)} OK")


def test_risk_scoring():
    findings = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    scored = assign_risk_score(findings)
    for f in scored:
        assert 0.0 <= f.risk_score <= 10.0
    sqli = scored[0]
    assert sqli.risk_score > 7.0, f"Expected high risk score for SQLi, got {sqli.risk_score}"
    print(f"  risk scoring: sqli={sqli.risk_score}, secret={scored[1].risk_score} OK")


if __name__ == "__main__":
    test_dedup_same_scanner()
    test_dedup_cross_scanner()
    test_risk_scoring()
    print("\nAll dedup/scoring tests passed.")
