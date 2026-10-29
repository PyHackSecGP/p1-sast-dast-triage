"""Tests for agent tools — uses existing fixtures in tests/fixtures/."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest.mock as mock
import uuid
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.tools import (
    _STORE,
    apply_suppressions,
    deduplicate_findings,
    filter_false_positives,
    generate_report,
    parse_bandit,
    parse_nuclei,
    parse_semgrep,
    parse_trivy,
    parse_zap,
    score_findings,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fresh_sid() -> str:
    """Return a unique session_id per test to avoid store leakage."""
    return str(uuid.uuid4())[:8]


# ── Parser tools ─────────────────────────────────────────────────────────────

def test_parse_semgrep_populates_store():
    sid = fresh_sid()
    result = json.loads(parse_semgrep(file=f"{FIXTURES}/semgrep_sample.json", session_id=sid))
    assert result["count"] == 2
    assert result["session_id"] == sid
    assert len(_STORE[sid]) == 2


def test_parse_bandit_populates_store():
    sid = fresh_sid()
    result = json.loads(parse_bandit(file=f"{FIXTURES}/bandit_sample.json", session_id=sid))
    assert result["count"] == 2
    assert _STORE[sid][0].scanner == "bandit"


def test_parse_zap_populates_store():
    sid = fresh_sid()
    result = json.loads(parse_zap(file=f"{FIXTURES}/zap_sample.xml", session_id=sid))
    assert result["count"] == 2
    assert _STORE[sid][0].scanner == "zap"


def test_parse_trivy_populates_store():
    sid = fresh_sid()
    result = json.loads(parse_trivy(file=f"{FIXTURES}/trivy_sample.json", session_id=sid))
    assert result["count"] == 4  # 2 vulns + 1 misconfig + 1 secret
    assert _STORE[sid][0].scanner == "trivy"


def test_parse_nuclei_populates_store():
    sid = fresh_sid()
    result = json.loads(parse_nuclei(file=f"{FIXTURES}/nuclei_sample.jsonl", session_id=sid))
    assert result["count"] == 3
    assert _STORE[sid][0].scanner == "nuclei"


def test_parse_missing_file_returns_error():
    sid = fresh_sid()
    result = json.loads(parse_semgrep(file="/nonexistent/path.json", session_id=sid))
    assert "error" in result


# ── Pipeline tools ────────────────────────────────────────────────────────────

def test_deduplicate_findings_reduces_count():
    sid = fresh_sid()
    parse_semgrep(file=f"{FIXTURES}/semgrep_sample.json", session_id=sid)
    # semgrep_sample.json has 2 unique findings — dedup keeps both
    result = json.loads(deduplicate_findings(session_id=sid))
    assert result["after"] <= result["before"]
    assert result["session_id"] == sid
    assert len(_STORE[sid]) == result["after"]


def test_score_findings_assigns_nonzero_scores():
    sid = fresh_sid()
    parse_semgrep(file=f"{FIXTURES}/semgrep_sample.json", session_id=sid)
    deduplicate_findings(session_id=sid)
    result = json.loads(score_findings(session_id=sid))
    assert result["count"] > 0
    assert all(f.risk_score > 0 for f in _STORE[sid])
    assert "by_severity" in result
    assert sum(result["by_severity"].values()) == result["count"]


def test_apply_suppressions_skips_missing_file():
    sid = fresh_sid()
    parse_semgrep(file=f"{FIXTURES}/semgrep_sample.json", session_id=sid)
    result = json.loads(apply_suppressions(session_id=sid, ruleset="/nonexistent/suppressions.yaml"))
    assert result["suppressed"] == 0
    assert result["active"] == 2


def test_apply_suppressions_suppresses_matching():
    sid = fresh_sid()
    parse_semgrep(file=f"{FIXTURES}/semgrep_sample.json", session_id=sid)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("- rule_id: python.lang.security.audit.sqli.raw-query-format-string\n")
        f.write("  reason: test suppression\n")
        sup_path = f.name
    try:
        result = json.loads(apply_suppressions(session_id=sid, ruleset=sup_path))
        assert result["suppressed"] == 1
        assert result["active"] == 1
    finally:
        os.unlink(sup_path)


# ── FP filter + report tools ──────────────────────────────────────────────────

def test_filter_false_positives_marks_fps():
    sid = fresh_sid()
    parse_semgrep(file=f"{FIXTURES}/semgrep_sample.json", session_id=sid)
    deduplicate_findings(session_id=sid)
    score_findings(session_id=sid)

    def fake_filter(findings, verbose=False):
        if findings:
            findings[0].status = "likely_fp"
            findings[0].confidence = 0.9
        return findings

    with mock.patch("agent.tools._core_filter_fp", side_effect=fake_filter):
        result = json.loads(filter_false_positives(session_id=sid))

    assert result["likely_fp"] == 1
    assert result["confirmed"] == 1


def test_generate_report_writes_json(tmp_path):
    sid = fresh_sid()
    parse_semgrep(file=f"{FIXTURES}/semgrep_sample.json", session_id=sid)
    result = json.loads(generate_report(session_id=sid, format="json", output_dir=str(tmp_path)))
    assert len(result["files"]) == 1
    assert result["files"][0].endswith(".json")
    assert Path(result["files"][0]).exists()


def test_generate_report_writes_all_formats(tmp_path):
    sid = fresh_sid()
    parse_semgrep(file=f"{FIXTURES}/semgrep_sample.json", session_id=sid)
    result = json.loads(generate_report(session_id=sid, format="all", output_dir=str(tmp_path)))
    assert len(result["files"]) == 4  # json + markdown + sarif + html


# ── Empty-store / error-path coverage ─────────────────────────────────────────

def test_deduplicate_findings_empty_store():
    """Dedup on unknown session_id returns 0/0, no crash."""
    result = json.loads(deduplicate_findings(session_id=fresh_sid()))
    assert result["before"] == 0
    assert result["after"] == 0


def test_score_findings_empty_store():
    """Scoring on empty store returns count=0 and empty breakdown."""
    result = json.loads(score_findings(session_id=fresh_sid()))
    assert result["count"] == 0
    assert result["by_severity"] == {}


def test_apply_suppressions_empty_store():
    """Suppressions on empty store returns 0 suppressed / 0 active."""
    result = json.loads(apply_suppressions(session_id=fresh_sid(), ruleset="/nonexistent.yaml"))
    assert result["suppressed"] == 0
    assert result["active"] == 0


def test_generate_report_invalid_format_returns_error(tmp_path):
    """Invalid format string surfaces as 'error' key, no file written."""
    sid = fresh_sid()
    parse_semgrep(file=f"{FIXTURES}/semgrep_sample.json", session_id=sid)
    result = json.loads(generate_report(session_id=sid, format="pdf", output_dir=str(tmp_path)))
    assert "error" in result
    assert list(tmp_path.iterdir()) == []


def test_generate_report_markdown_only(tmp_path):
    """format='markdown' writes exactly one .md file."""
    sid = fresh_sid()
    parse_semgrep(file=f"{FIXTURES}/semgrep_sample.json", session_id=sid)
    result = json.loads(generate_report(session_id=sid, format="markdown", output_dir=str(tmp_path)))
    assert len(result["files"]) == 1
    assert result["files"][0].endswith(".md")


def test_filter_false_positives_error_propagates():
    """If core filter raises, tool wrapper returns an 'error' JSON key (not an exception)."""
    sid = fresh_sid()
    parse_semgrep(file=f"{FIXTURES}/semgrep_sample.json", session_id=sid)

    def boom(findings, verbose=False):
        raise RuntimeError("LLM unreachable")

    with mock.patch("agent.tools._core_filter_fp", side_effect=boom):
        result = json.loads(filter_false_positives(session_id=sid))
    assert "error" in result
    assert "LLM unreachable" in result["error"]


def test_parse_bandit_missing_file_returns_error():
    """Non-semgrep parser tool also surfaces missing-file as 'error' key."""
    result = json.loads(parse_bandit(file="/nonexistent/bandit.json", session_id=fresh_sid()))
    assert "error" in result
