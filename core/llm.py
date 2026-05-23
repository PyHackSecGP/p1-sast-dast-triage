"""LLM-powered false positive filter using claw-core Ollama endpoint."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from parsers.base import Finding

OLLAMA_URL = "http://100.126.22.55:11434/api/generate"
MODEL = "llama3.1:70b"

_SYSTEM = (
    "You are a senior application security engineer reviewing SAST/DAST scanner findings. "
    "Classify each finding as a true positive or false positive. "
    "Respond ONLY with a JSON object: {\"verdict\": \"true_positive\" | \"false_positive\", \"reason\": \"<one sentence>\"}"
)


def _build_prompt(f: Finding) -> str:
    parts = [
        f"Scanner: {f.scanner}",
        f"Rule: {f.rule_id}",
        f"Severity: {f.severity} (CVSS {f.cvss_score})",
        f"File: {f.file_path}" + (f":{f.line_number}" if f.line_number else ""),
        f"Finding: {f.title}",
        f"Message: {f.message}",
    ]
    if f.code_snippet:
        parts.append(f"Code:\n{f.code_snippet}")
    if f.cwe:
        parts.append(f"CWE: {f.cwe}")
    return "\n".join(parts)


def _query_ollama(prompt: str) -> dict:
    payload = json.dumps({
        "model": MODEL,
        "prompt": f"{_SYSTEM}\n\n{prompt}",
        "stream": False,
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def filter_false_positives(
    findings: list[Finding],
    verbose: bool = False,
) -> list[Finding]:
    """Run each finding through claw-core LLM and tag false positives.

    Findings that fail the LLM call are left unreviewed (false_positive=None)
    rather than dropped, so the user can still see them.
    """
    for i, f in enumerate(findings, 1):
        if verbose:
            print(f"  [{i}/{len(findings)}] {f.scanner} — {f.title[:60]}", end=" ... ", flush=True)
        try:
            result = _query_ollama(_build_prompt(f))
            response_text = result.get("response", "")
            # Extract JSON from response (model may wrap it in markdown fences)
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            verdict_data = json.loads(response_text[start:end])
            f.false_positive = verdict_data.get("verdict") == "false_positive"
            f.fp_reason = verdict_data.get("reason", "")
            if verbose:
                label = "FP" if f.false_positive else "TP"
                print(f"[{label}] {f.fp_reason[:60]}")
        except (urllib.error.URLError, json.JSONDecodeError, ValueError) as e:
            if verbose:
                print(f"[SKIP — {e}]")
    return findings
