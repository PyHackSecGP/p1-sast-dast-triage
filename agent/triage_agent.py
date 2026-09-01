"""TriageAgent — wraps agent-core.Agent for SAST/DAST triage workflow."""
from __future__ import annotations
import uuid

from agent_core import Agent, ToolRegistry
from agent_core.llm.base import LLMProvider
from agent_core.llm import get_provider
from agent_core.models import AgentResult, ExecutionPolicy

from .tools import (
    parse_semgrep, parse_bandit, parse_zap, parse_trivy, parse_nuclei,
    deduplicate_findings, score_findings, apply_suppressions,
    filter_false_positives, generate_report,
)

_ALL_TOOLS = [
    parse_semgrep, parse_bandit, parse_zap, parse_trivy, parse_nuclei,
    deduplicate_findings, score_findings, apply_suppressions,
    filter_false_positives, generate_report,
]

_SYSTEM_PROMPT = """\
You are a SAST/DAST triage agent. You orchestrate security scanner output through a pipeline:
parse → deduplicate → score → suppress → (optionally) filter false positives → generate report.

Tools are deterministic — call them in order as specified in the goal. The session_id is
provided in your goal; pass it unchanged to every tool call. After generate_report, summarize
the findings: total count, severity breakdown, and any notable high/critical issues.
"""


class TriageAgent:
    """Wraps agent-core.Agent with triage-specific tools and goal building."""

    def __init__(
        self,
        provider: LLMProvider | None = None,
        policy: ExecutionPolicy = ExecutionPolicy.SAFE,
        max_iterations: int = 20,
    ) -> None:
        """Initialise TriageAgent.

        Args:
            provider: LLM provider to use. Defaults to get_provider() if None.
            policy: Execution policy controlling which tool risks are permitted.
            max_iterations: Maximum agent loop iterations before giving up.
        """
        self._provider = provider or get_provider()
        self._policy = policy
        self._max_iterations = max_iterations

    def run(
        self,
        input_file: str,
        scanner: str,
        session_id: str = "",
        suppress_file: str = "suppressions.yaml",
        format: str = "all",
        output_dir: str = ".",
        run_fp_filter: bool = False,
    ) -> AgentResult:
        """Run the triage pipeline as an agent loop.

        Args:
            input_file: Path to the scanner output file to triage.
            scanner: Scanner name (semgrep, bandit, zap, trivy, nuclei).
            session_id: Session identifier; auto-generated if empty.
            suppress_file: Path to suppressions YAML ruleset.
            format: Report format — json, markdown, sarif, html, or all.
            output_dir: Directory to write report files into.
            run_fp_filter: Whether to run the LLM false-positive filter step.

        Returns:
            AgentResult with output text, stop reason, and full tool-call audit trail.
        """
        VALID_SCANNERS = {"semgrep", "bandit", "zap", "trivy", "nuclei"}
        if scanner not in VALID_SCANNERS:
            raise ValueError(f"Unknown scanner {scanner!r}. Valid: {sorted(VALID_SCANNERS)}")

        sid = session_id or str(uuid.uuid4())[:8]

        fp_step = f'5. filter_false_positives(session_id="{sid}")\n' if run_fp_filter else ""
        report_step = "6" if run_fp_filter else "5"

        goal = (
            f"Triage SAST/DAST findings from: {input_file}\n"
            f"Scanner: {scanner}\n"
            f"Session ID: {sid}\n\n"
            f"Execute these steps in order:\n"
            f'1. parse_{scanner}(file="{input_file}", session_id="{sid}")\n'
            f'2. deduplicate_findings(session_id="{sid}")\n'
            f'3. score_findings(session_id="{sid}")\n'
            f'4. apply_suppressions(session_id="{sid}", ruleset="{suppress_file}")\n'
            f"{fp_step}"
            f'{report_step}. generate_report(session_id="{sid}", format="{format}", output_dir="{output_dir}")\n\n'
            f"Then summarize the results."
        )

        registry = ToolRegistry(_ALL_TOOLS)
        agent = Agent(
            provider=self._provider,
            registry=registry,
            policy=self._policy,
            max_iterations=self._max_iterations,
            system_prompt=_SYSTEM_PROMPT,
            name="TriageAgent",
        )
        return agent.run(goal)
