"""Tests for core/suppression.py — suppression file loading and matching."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.suppression import apply_suppressions
from parsers.base import Finding


def _finding(rule_id: str, file_path: str = "app/db.py") -> Finding:
    return Finding(
        scanner="semgrep",
        rule_id=rule_id,
        title=rule_id,
        severity="high",
        message="test",
        file_path=file_path,
        line_number=1,
    )


def _write_suppression(tmp_path, content: str) -> str:
    p = tmp_path / "suppressions.yaml"
    p.write_text(content)
    return str(p)


def test_suppress_by_rule_id(tmp_path) -> None:
    path = _write_suppression(tmp_path, "- rule_id: B105\n  reason: accepted risk\n")
    findings = [_finding("B105"), _finding("B601")]
    apply_suppressions(findings, path)
    assert findings[0].status == "suppressed"
    assert findings[0].fp_reason == "accepted risk"
    assert findings[1].status == "confirmed"


def test_suppress_by_file_glob(tmp_path) -> None:
    path = _write_suppression(tmp_path, "- file_glob: tests/*\n  reason: test fixtures\n")
    findings = [_finding("B105", "tests/fixture.py"), _finding("B105", "app/db.py")]
    apply_suppressions(findings, path)
    assert findings[0].status == "suppressed"
    assert findings[1].status == "confirmed"


def test_suppress_both_conditions_and_logic(tmp_path) -> None:
    """rule_id + file_glob together: BOTH must match."""
    path = _write_suppression(
        tmp_path,
        "- rule_id: B105\n  file_glob: config/*\n  reason: template token\n",
    )
    # rule matches but file doesn't — not suppressed
    findings = [
        _finding("B105", "app/db.py"),
        _finding("B105", "config/settings.py"),
        _finding("B601", "config/settings.py"),
    ]
    apply_suppressions(findings, path)
    assert findings[0].status == "confirmed"
    assert findings[1].status == "suppressed"
    assert findings[2].status == "confirmed"


def test_no_suppression_file_is_noop(tmp_path) -> None:
    """Missing file → no findings touched."""
    findings = [_finding("B105")]
    apply_suppressions(findings, str(tmp_path / "does_not_exist.yaml"))
    assert findings[0].status == "confirmed"


def test_empty_rule_no_match(tmp_path) -> None:
    """A rule with neither rule_id nor file_glob matches nothing."""
    path = _write_suppression(tmp_path, "- reason: pointless rule\n")
    findings = [_finding("B105")]
    apply_suppressions(findings, path)
    assert findings[0].status == "confirmed"


def test_multiple_rules_first_match_wins(tmp_path) -> None:
    """Finding matches two rules — first match sets reason, no double-counting."""
    path = _write_suppression(
        tmp_path,
        "- rule_id: B105\n  reason: first\n- rule_id: B105\n  reason: second\n",
    )
    findings = [_finding("B105")]
    apply_suppressions(findings, path)
    assert findings[0].status == "suppressed"
    assert findings[0].fp_reason == "first"
