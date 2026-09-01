"""Tool-calling wrappers around P1's existing parsers, core, and output modules."""
from __future__ import annotations
import json
from typing import Any

from agent_core import tool
from agent_core.models import ToolRisk

from core.dedup import deduplicate
from core.scorer import assign_risk_score
from core.suppression import apply_suppressions as _core_apply_suppressions
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


@tool(description="Deduplicate findings by CWE+file+line. Multi-scanner agreement is preserved in sources list.", risk=ToolRisk.NONE)
def deduplicate_findings(session_id: str) -> str:
    """Merge duplicate findings in the session store. Returns before/after counts."""
    try:
        findings = _STORE.get(session_id, [])
        before = len(findings)
        deduped = deduplicate(findings)
        _STORE[session_id] = deduped
        return json.dumps({"session_id": session_id, "before": before, "after": len(deduped)})
    except Exception as exc:
        return json.dumps({"session_id": session_id, "error": str(exc)})


@tool(description="Score findings using CWE heuristics (0-10) and multi-scanner agreement bump.", risk=ToolRisk.NONE)
def score_findings(session_id: str) -> str:
    """Assign risk_score to each finding. Returns count and severity breakdown."""
    try:
        findings = _STORE.get(session_id, [])
        scored = assign_risk_score(findings)
        _STORE[session_id] = scored
        by_sev: dict[str, int] = {}
        for f in scored:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return json.dumps({"session_id": session_id, "count": len(scored), "by_severity": by_sev})
    except Exception as exc:
        return json.dumps({"session_id": session_id, "error": str(exc)})


@tool(description="Apply suppressions.yaml rules to mark known-good findings as suppressed. Safe to call even if file absent.", risk=ToolRisk.NONE)
def apply_suppressions(session_id: str, ruleset: str) -> str:
    """Mark findings matching suppression rules as status='suppressed'. Skips gracefully if file absent."""
    try:
        findings = _STORE.get(session_id, [])
        updated = _core_apply_suppressions(findings, ruleset)
        _STORE[session_id] = updated
        suppressed = sum(1 for f in updated if f.status == "suppressed")
        active = sum(1 for f in updated if f.status != "suppressed")
        return json.dumps({"session_id": session_id, "suppressed": suppressed, "active": active})
    except Exception as exc:
        return json.dumps({"session_id": session_id, "error": str(exc)})
