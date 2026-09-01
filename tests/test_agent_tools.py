"""Tests for agent tools — uses existing fixtures in tests/fixtures/."""
from __future__ import annotations
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.tools import (
    parse_semgrep, parse_bandit, parse_zap, parse_trivy, parse_nuclei,
    _STORE,
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
