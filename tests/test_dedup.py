"""Tests for deduplication (merge semantics) and risk scoring."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.dedup import deduplicate
from core.scorer import assign_risk_score
from parsers import BanditParser, SemgrepParser
from parsers.base import Finding

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _finding(scanner: str, rule_id: str, severity: str = "high", **kw) -> Finding:
    defaults = {
        "title": rule_id,
        "message": f"{scanner} says: {rule_id}",
        "file_path": "app/db.py",
        "line_number": 42,
        "cwe": "CWE-89",
    }
    defaults.update(kw)
    return Finding(scanner=scanner, rule_id=rule_id, severity=severity, **defaults)


# ── same-scanner dedup ────────────────────────────────────────────────────────

def test_dedup_same_scanner_collapses_duplicates() -> None:
    findings = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    duped = findings + findings
    result = deduplicate(duped)
    assert len(result) == len(findings)


def test_dedup_same_scanner_source_stays_singleton() -> None:
    """Two Semgrep findings for the same rule collapse to one source entry."""
    f = _finding("semgrep", "sql-injection")
    result = deduplicate([f, f])
    assert len(result) == 1
    assert result[0].sources == ["semgrep:sql-injection"]


# ── cross-scanner merge ───────────────────────────────────────────────────────

def test_dedup_cross_scanner_merges_sources() -> None:
    """Two scanners agree — the survivor carries both sources."""
    semgrep = _finding("semgrep", "python.django.sql-injection", severity="high")
    bandit = _finding("bandit", "B608", severity="medium")

    result = deduplicate([semgrep, bandit])

    assert len(result) == 1, "Duplicates must collapse to a single finding"
    survivor = result[0]
    # High severity wins over medium
    assert survivor.severity == "high"
    # Both scanners recorded in sources — order = insertion order
    assert survivor.sources == [
        "semgrep:python.django.sql-injection",
        "bandit:B608",
    ]


def test_dedup_reversed_order_still_max_severity() -> None:
    """Merge picks max severity regardless of input order."""
    semgrep = _finding("semgrep", "sqli", severity="high")
    bandit = _finding("bandit", "B608", severity="medium")

    survivor_a = deduplicate([bandit, semgrep])[0]
    survivor_b = deduplicate([semgrep, bandit])[0]

    assert survivor_a.severity == survivor_b.severity == "high"
    assert set(survivor_a.sources) == set(survivor_b.sources)


def test_dedup_prefers_longest_message() -> None:
    a = _finding("semgrep", "sqli", message="short")
    b = _finding("bandit", "B608", message="a considerably richer explanation")
    merged = deduplicate([a, b])[0]
    assert merged.message == "a considerably richer explanation"


def test_dedup_prefers_longest_code_snippet() -> None:
    a = _finding("semgrep", "sqli", code_snippet="x=1")
    b = _finding(
        "bandit", "B608",
        code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
    )
    merged = deduplicate([a, b])[0]
    assert "cursor.execute" in merged.code_snippet


def test_dedup_from_fixtures_end_to_end() -> None:
    semgrep = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    bandit = BanditParser().parse(f"{FIXTURES}/bandit_sample.json")
    combined = semgrep + bandit
    result = deduplicate(combined)
    # Semgrep and Bandit each report SQLi at app/db.py:42 (CWE-89) — those merge.
    assert len(result) == len(combined) - 1
    # The merged SQLi finding now carries two sources.
    sqli = next(f for f in result if f.cwe == "CWE-89")
    assert len(sqli.sources) == 2


# ── scorer ────────────────────────────────────────────────────────────────────

def test_risk_scoring_baseline() -> None:
    findings = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    scored = assign_risk_score(findings)
    for f in scored:
        assert 0.0 <= f.risk_score <= 10.0
    sqli = scored[0]
    assert sqli.risk_score > 7.0


def test_agreement_boosts_score() -> None:
    """Two scanners agreeing pushes the risk score above a single-scanner hit."""
    single = _finding("semgrep", "sqli", severity="high")
    assign_risk_score([single])

    a = _finding("semgrep", "sqli", severity="high")
    b = _finding("bandit", "B608", severity="high")
    merged = deduplicate([a, b])
    assign_risk_score(merged)

    assert merged[0].risk_score > single.risk_score, (
        "Multi-scanner agreement must raise the risk score"
    )


def test_agreement_score_capped_at_ten() -> None:
    """A critical CWE-89 finding with many agreeing scanners still tops out at 10.0."""
    findings = [
        _finding(f"scanner{i}", f"rule{i}", severity="critical")
        for i in range(10)
    ]
    merged = deduplicate(findings)
    assign_risk_score(merged)
    assert merged[0].risk_score == 10.0


def test_sources_seeded_by_post_init() -> None:
    """Manually-constructed findings still get a sources entry."""
    f = _finding("semgrep", "sqli")
    assert f.sources == ["semgrep:sqli"]
