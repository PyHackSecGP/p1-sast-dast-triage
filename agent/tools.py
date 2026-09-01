"""Tool-calling wrappers around P1's existing parsers, core, and output modules."""
from __future__ import annotations
import json
from typing import Any

from agent_core import tool
from agent_core.models import ToolRisk

from parsers import SemgrepParser, BanditParser, ZapParser, TrivyParser, NucleiParser
from parsers.base import Finding

# Module-level session store. Key = session_id, value = list[Finding].
# Tools write here; the agent memory holds only JSON summaries.
# Intentionally not evicted — P1 is a CLI tool; each invocation creates one session.
_STORE: dict[str, list[Finding]] = {}


def _summarize(findings: list[Finding], session_id: str, extra: dict[str, Any] | None = None) -> str:
    """Return JSON summary of findings for LLM context (top-5 sample)."""
    sample = [
        {"title": f.title, "severity": f.severity, "file": f.file_path,
         "cwe": f.cwe, "risk": f.risk_score, "status": f.status}
        for f in findings[:5]
    ]
    result: dict[str, Any] = {"session_id": session_id, "count": len(findings), "sample": sample}
    if extra:
        result.update(extra)
    return json.dumps(result)


@tool(description="Parse Semgrep JSON output file and load findings into the session store.", risk=ToolRisk.NONE)
def parse_semgrep(file: str, session_id: str) -> str:
    """Parse Semgrep --json output. Returns JSON summary with finding count."""
    try:
        findings = SemgrepParser().parse(file)
        _STORE[session_id] = findings
        return _summarize(findings, session_id)
    except Exception as exc:
        return json.dumps({"session_id": session_id, "error": str(exc)})


@tool(description="Parse Bandit JSON output file and load findings into the session store.", risk=ToolRisk.NONE)
def parse_bandit(file: str, session_id: str) -> str:
    """Parse Bandit --format json output. Returns JSON summary with finding count."""
    try:
        findings = BanditParser().parse(file)
        _STORE[session_id] = findings
        return _summarize(findings, session_id)
    except Exception as exc:
        return json.dumps({"session_id": session_id, "error": str(exc)})


@tool(description="Parse OWASP ZAP XML output file and load findings into the session store.", risk=ToolRisk.NONE)
def parse_zap(file: str, session_id: str) -> str:
    """Parse ZAP XML report. Returns JSON summary with finding count."""
    try:
        findings = ZapParser().parse(file)
        _STORE[session_id] = findings
        return _summarize(findings, session_id)
    except Exception as exc:
        return json.dumps({"session_id": session_id, "error": str(exc)})


@tool(description="Parse Trivy JSON output file and load findings into the session store.", risk=ToolRisk.NONE)
def parse_trivy(file: str, session_id: str) -> str:
    """Parse Trivy --format json output. Returns JSON summary with finding count."""
    try:
        findings = TrivyParser().parse(file)
        _STORE[session_id] = findings
        return _summarize(findings, session_id)
    except Exception as exc:
        return json.dumps({"session_id": session_id, "error": str(exc)})


@tool(description="Parse Nuclei JSONL output file and load findings into the session store.", risk=ToolRisk.NONE)
def parse_nuclei(file: str, session_id: str) -> str:
    """Parse Nuclei -j output. Returns JSON summary with finding count."""
    try:
        findings = NucleiParser().parse(file)
        _STORE[session_id] = findings
        return _summarize(findings, session_id)
    except Exception as exc:
        return json.dumps({"session_id": session_id, "error": str(exc)})
