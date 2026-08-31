"""Tests for core/llm.py: JSON extractor + filter failure modes.

Mocks urllib at the boundary — zero network.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.llm import _extract_json, filter_false_positives
from parsers.base import Finding

# ── _extract_json ─────────────────────────────────────────────────────────────


def test_extract_clean_json() -> None:
    assert _extract_json('{"verdict": "true_positive", "reason": "reachable"}') == {
        "verdict": "true_positive",
        "reason": "reachable",
    }


def test_extract_prose_wrapped_json() -> None:
    """llama3.2:3b commonly prefixes JSON with commentary."""
    text = 'Here is my analysis: {"verdict": "false_positive", "reason": "test file"}'
    assert _extract_json(text)["verdict"] == "false_positive"


def test_extract_nested_braces() -> None:
    """Balanced-brace walker handles nested objects."""
    text = '{"verdict": "true_positive", "meta": {"cwe": 89, "conf": {"level": "high"}}}'
    out = _extract_json(text)
    assert out["verdict"] == "true_positive"
    assert out["meta"]["conf"]["level"] == "high"


def test_extract_no_brace_raises_value_error() -> None:
    """Empty JSON is impossible to recover; must raise ValueError so the
    caller's except tuple catches it."""
    with pytest.raises(ValueError, match="No JSON object"):
        _extract_json("Sorry, I cannot classify this finding.")


def test_extract_empty_response_raises() -> None:
    with pytest.raises(ValueError, match="Empty response"):
        _extract_json("")


def test_extract_truncated_json_raises() -> None:
    """Unmatched braces — the walker must not silently return partial data."""
    with pytest.raises(ValueError, match="Unmatched braces"):
        _extract_json('{"verdict": "true_positive", "reason": "oh no')


def test_extract_malformed_json_raises_json_decode() -> None:
    with pytest.raises(json.JSONDecodeError):
        _extract_json("{verdict: no_quotes}")


# ── filter_false_positives ────────────────────────────────────────────────────


def _make_finding() -> Finding:
    return Finding(
        scanner="semgrep",
        rule_id="python.django.sql-injection",
        title="sql-injection",
        severity="high",
        message="SQLi in query",
        file_path="app/db.py",
        line_number=42,
        code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        cwe="CWE-89",
    )


def _mock_query(response_text: str):
    """Build a patch context that returns the given response text."""
    return patch("core.llm._query_ollama", return_value={"response": response_text})


def test_filter_marks_true_positive() -> None:
    f = _make_finding()
    with _mock_query('{"verdict": "true_positive", "confidence": 0.92, "reason": "reachable via /search"}'):
        out = filter_false_positives([f])
    assert out[0].false_positive is False
    assert out[0].status == "confirmed"
    assert out[0].fp_reason == "reachable via /search"
    assert out[0].confidence == 0.92


def test_filter_marks_false_positive() -> None:
    f = _make_finding()
    with _mock_query('{"verdict": "false_positive", "confidence": 0.85, "reason": "user_id validated at line 30"}'):
        out = filter_false_positives([f])
    assert out[0].false_positive is True
    assert out[0].status == "likely_fp"
    assert out[0].confidence == 0.85


def test_filter_confidence_clamped() -> None:
    """Confidence values outside [0, 1] get clamped."""
    f = _make_finding()
    with _mock_query('{"verdict": "true_positive", "confidence": 1.5, "reason": "overflow"}'):
        out = filter_false_positives([f])
    assert out[0].confidence == 1.0


def test_filter_missing_confidence_stays_none() -> None:
    """LLM that omits confidence field leaves Finding.confidence as None."""
    f = _make_finding()
    with _mock_query('{"verdict": "true_positive", "reason": "no confidence given"}'):
        out = filter_false_positives([f])
    assert out[0].confidence is None


def test_filter_no_brace_leaves_unreviewed() -> None:
    """Prose-only response is unrecoverable — do not silently confirm."""
    f = _make_finding()
    assert f.status == "confirmed"  # default
    with _mock_query("I cannot classify this."):
        out = filter_false_positives([f])
    assert out[0].status == "unreviewed"
    assert "No JSON object" in out[0].fp_reason


def test_filter_url_error_leaves_unreviewed() -> None:
    f = _make_finding()
    with patch("core.llm._query_ollama", side_effect=urllib.error.URLError("connection refused")):
        out = filter_false_positives([f])
    assert out[0].status == "unreviewed"
    assert "llm_error" in out[0].fp_reason


def test_filter_timeout_leaves_unreviewed() -> None:
    f = _make_finding()
    with patch("core.llm._query_ollama", side_effect=TimeoutError("read timed out")):
        out = filter_false_positives([f])
    assert out[0].status == "unreviewed"


def test_filter_missing_verdict_leaves_unreviewed() -> None:
    """JSON parses but has no 'verdict' key — treat as unreviewed, not confirmed."""
    f = _make_finding()
    with _mock_query('{"reason": "I forgot the verdict"}'):
        out = filter_false_positives([f])
    assert out[0].status == "unreviewed"


def test_filter_invalid_verdict_value_leaves_unreviewed() -> None:
    f = _make_finding()
    with _mock_query('{"verdict": "maybe", "reason": "unsure"}'):
        out = filter_false_positives([f])
    assert out[0].status == "unreviewed"
