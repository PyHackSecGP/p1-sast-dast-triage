"""Integration tests for TriageAgent using MockProvider."""
from __future__ import annotations
import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_core.llm.base import LLMProvider
from agent_core.models import LLMResponse, ToolCall, StopReason

from agent.triage_agent import TriageAgent

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class MockProvider(LLMProvider):
    def __init__(self, responses: list[LLMResponse]) -> None:
        self._iter = iter(responses)

    def chat(self, messages, tools) -> LLMResponse:
        return next(self._iter)


def test_triage_agent_full_pipeline():
    """Agent calls parse → dedup → score → suppress → generate_report → DONE."""
    with tempfile.TemporaryDirectory() as out_dir:
        sid = "test-sid-001"
        semgrep_file = f"{FIXTURES}/semgrep_sample.json"

        provider = MockProvider([
            LLMResponse(tool_calls=[ToolCall(name="parse_semgrep", arguments={"file": semgrep_file, "session_id": sid}, call_id="1")]),
            LLMResponse(tool_calls=[ToolCall(name="deduplicate_findings", arguments={"session_id": sid}, call_id="2")]),
            LLMResponse(tool_calls=[ToolCall(name="score_findings", arguments={"session_id": sid}, call_id="3")]),
            LLMResponse(tool_calls=[ToolCall(name="apply_suppressions", arguments={"session_id": sid, "ruleset": "/nonexistent.yaml"}, call_id="4")]),
            LLMResponse(tool_calls=[ToolCall(name="generate_report", arguments={"session_id": sid, "format": "json", "output_dir": out_dir}, call_id="5")]),
            LLMResponse(content="Triage complete. Found 2 findings: 1 high (SQL injection), 1 medium (hardcoded secret)."),
        ])

        agent = TriageAgent(provider=provider)
        result = agent.run(
            input_file=semgrep_file,
            scanner="semgrep",
            session_id=sid,
            output_dir=out_dir,
            format="json",
        )

        assert result.stop_reason == StopReason.DONE
        assert result.output is not None
        assert len(result.tool_calls) == 5
        assert result.tool_calls[0].name == "parse_semgrep"
        assert result.tool_calls[-1].name == "generate_report"


def test_triage_agent_audit_trail_complete():
    """All tool calls appear in AgentResult.tool_calls."""
    sid = "test-sid-002"
    semgrep_file = f"{FIXTURES}/semgrep_sample.json"
    with tempfile.TemporaryDirectory() as out_dir:
        provider = MockProvider([
            LLMResponse(tool_calls=[ToolCall(name="parse_semgrep", arguments={"file": semgrep_file, "session_id": sid}, call_id="a")]),
            LLMResponse(tool_calls=[ToolCall(name="deduplicate_findings", arguments={"session_id": sid}, call_id="b")]),
            LLMResponse(tool_calls=[ToolCall(name="score_findings", arguments={"session_id": sid}, call_id="c")]),
            LLMResponse(tool_calls=[ToolCall(name="generate_report", arguments={"session_id": sid, "format": "json", "output_dir": out_dir}, call_id="d")]),
            LLMResponse(content="done"),
        ])
        agent = TriageAgent(provider=provider)
        result = agent.run(input_file=semgrep_file, scanner="semgrep", session_id=sid, output_dir=out_dir, format="json")
        names = [tc.name for tc in result.tool_calls]
        assert "parse_semgrep" in names
        assert "generate_report" in names
