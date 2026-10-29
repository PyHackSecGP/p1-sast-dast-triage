"""Integration tests for TriageAgent using MockProvider."""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_core.llm.base import LLMProvider
from agent_core.models import LLMResponse, StopReason, ToolCall

from agent.triage_agent import TriageAgent

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class MockProvider(LLMProvider):
    def __init__(self, responses: list[LLMResponse]) -> None:
        self._iter = iter(responses)
        self.seen_goals: list[str] = []

    def chat(self, messages, tools) -> LLMResponse:
        # Capture the user goal (first non-system message) for routing assertions.
        for m in messages:
            if m.role == "user" and m.content:
                self.seen_goals.append(m.content)
                break
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


def test_triage_agent_partial_pipeline_still_produces_result():
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


def test_triage_agent_with_fp_filter():
    """Agent correctly inserts filter_false_positives step when run_fp_filter=True."""
    sid = "test-sid-003"
    semgrep_file = f"{FIXTURES}/semgrep_sample.json"
    with tempfile.TemporaryDirectory() as out_dir:
        provider = MockProvider([
            LLMResponse(tool_calls=[ToolCall(name="parse_semgrep", arguments={"file": semgrep_file, "session_id": sid}, call_id="1")]),
            LLMResponse(tool_calls=[ToolCall(name="deduplicate_findings", arguments={"session_id": sid}, call_id="2")]),
            LLMResponse(tool_calls=[ToolCall(name="score_findings", arguments={"session_id": sid}, call_id="3")]),
            LLMResponse(tool_calls=[ToolCall(name="apply_suppressions", arguments={"session_id": sid, "ruleset": "suppressions.yaml"}, call_id="4")]),
            LLMResponse(tool_calls=[ToolCall(name="filter_false_positives", arguments={"session_id": sid}, call_id="5")]),
            LLMResponse(tool_calls=[ToolCall(name="generate_report", arguments={"session_id": sid, "format": "json", "output_dir": out_dir}, call_id="6")]),
            LLMResponse(content="Triage complete with FP filter."),
        ])
        agent = TriageAgent(provider=provider)
        result = agent.run(
            input_file=semgrep_file,
            scanner="semgrep",
            session_id=sid,
            output_dir=out_dir,
            format="json",
            run_fp_filter=True,
        )
        assert result.stop_reason == StopReason.DONE
        names = [tc.name for tc in result.tool_calls]
        assert "filter_false_positives" in names
        assert "generate_report" in names
        assert len(result.tool_calls) == 6


# ── Routing / argument-wiring coverage ───────────────────────────────────────

def test_triage_agent_invalid_scanner_raises():
    """Unknown scanner is rejected before the agent loop starts."""
    agent = TriageAgent(provider=MockProvider([]))
    with pytest.raises(ValueError, match="Unknown scanner"):
        agent.run(input_file="x.json", scanner="snyk")


def test_triage_agent_autogenerates_session_id_when_empty():
    """Empty session_id is replaced by an 8-char auto id and threaded into the goal."""
    sid_captured: list[str] = []

    class CaptureProvider(MockProvider):
        def chat(self, messages, tools):
            for m in messages:
                if m.role == "user" and m.content and not sid_captured:
                    # goal line: "Session ID: <sid>\n"
                    for line in m.content.splitlines():
                        if line.startswith("Session ID:"):
                            sid_captured.append(line.split(":", 1)[1].strip())
                            break
            return super().chat(messages, tools)

    provider = CaptureProvider([LLMResponse(content="done")])
    with tempfile.TemporaryDirectory() as out_dir:
        TriageAgent(provider=provider).run(
            input_file=f"{FIXTURES}/semgrep_sample.json",
            scanner="semgrep",
            session_id="",
            output_dir=out_dir,
            format="json",
        )
    assert len(sid_captured) == 1
    assert len(sid_captured[0]) == 8
    assert sid_captured[0] != ""


def test_triage_agent_goal_routes_fp_filter_step_in_goal_text():
    """run_fp_filter=True must inject filter_false_positives into the goal text passed to the LLM.

    This is the --agentic → right-tool routing contract: main.py sets run_fp_filter
    from args.llm, and TriageAgent must thread it into the step list.
    """
    provider = MockProvider([LLMResponse(content="stop")])
    with tempfile.TemporaryDirectory() as out_dir:
        TriageAgent(provider=provider).run(
            input_file=f"{FIXTURES}/semgrep_sample.json",
            scanner="semgrep",
            session_id="rt-01",
            output_dir=out_dir,
            format="json",
            run_fp_filter=True,
        )
    assert provider.seen_goals, "goal should have been sent to the provider"
    goal = provider.seen_goals[0]
    assert "filter_false_positives" in goal
    # Fp step is numbered 5, report is 6 when fp filter is on.
    assert "5. filter_false_positives" in goal
    assert "6. generate_report" in goal


def test_triage_agent_end_to_end_with_mocked_llm_writes_report(tmp_path):
    """End-to-end: mocked LLM drives the full pipeline and generate_report writes a real file."""
    sid = "e2e-01"
    semgrep_file = f"{FIXTURES}/semgrep_sample.json"
    provider = MockProvider([
        LLMResponse(tool_calls=[ToolCall(name="parse_semgrep", arguments={"file": semgrep_file, "session_id": sid}, call_id="1")]),
        LLMResponse(tool_calls=[ToolCall(name="deduplicate_findings", arguments={"session_id": sid}, call_id="2")]),
        LLMResponse(tool_calls=[ToolCall(name="score_findings", arguments={"session_id": sid}, call_id="3")]),
        LLMResponse(tool_calls=[ToolCall(name="apply_suppressions", arguments={"session_id": sid, "ruleset": "/nonexistent.yaml"}, call_id="4")]),
        LLMResponse(tool_calls=[ToolCall(name="generate_report", arguments={"session_id": sid, "format": "all", "output_dir": str(tmp_path)}, call_id="5")]),
        LLMResponse(content="Triage complete; 2 findings reported."),
    ])
    result = TriageAgent(provider=provider).run(
        input_file=semgrep_file,
        scanner="semgrep",
        session_id=sid,
        output_dir=str(tmp_path),
        format="all",
    )
    assert result.stop_reason == StopReason.DONE
    # All four report formats actually hit disk.
    written = sorted(p.suffix for p in tmp_path.iterdir())
    assert written == [".html", ".json", ".md", ".sarif"]
