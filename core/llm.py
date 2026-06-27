"""LLM-powered false positive filter using claw-core Ollama endpoint."""
from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request

from parsers.base import Finding

OLLAMA_URL = "http://100.126.22.55:11434/api/generate"
MODEL = "llama3.2:3b"   # 3B model stays loaded between calls; override with TRIAGE_MODEL env var
TIMEOUT = 300

_SYSTEM = (
    "You are a senior application security engineer reviewing SAST/DAST scanner findings. "
    "Classify each finding as a true positive or false positive. "
    "Respond ONLY with a JSON object: {\"verdict\": \"true_positive\" | \"false_positive\", \"reason\": \"<one sentence>\"}"
)


def _extract_json(text: str) -> dict:
    """Extract the first valid JSON object from model output."""
    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object found in response")
    # Walk forward from the first { to find the matching }
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("Unmatched braces in response")


def _build_prompt(f: Finding) -> str:
    parts = [
        f"Scanner: {f.scanner}",
        f"Rule: {f.rule_id}",
        f"Severity: {f.severity} (Risk Score {f.risk_score})",
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
    model = os.environ.get("TRIAGE_MODEL", MODEL)
    payload = json.dumps({
        "model": model,
        "prompt": f"{_SYSTEM}\n\n{prompt}",
        "stream": False,
    }).encode()

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    # Use default socket timeout so long inference runs don't get cut off.
    prev = socket.getdefaulttimeout()
    socket.setdefaulttimeout(TIMEOUT)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    finally:
        socket.setdefaulttimeout(prev)


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
            verdict_data = _extract_json(response_text)
            is_fp = verdict_data.get("verdict") == "false_positive"
            f.false_positive = is_fp
            f.fp_reason = verdict_data.get("reason", "")
            f.status = "likely_fp" if is_fp else "confirmed"
            if verbose:
                label = "FP" if is_fp else "TP"
                print(f"[{label}] {f.fp_reason[:60]}")
        except (urllib.error.URLError, json.JSONDecodeError, ValueError) as e:
            if verbose:
                print(f"[SKIP — {e}]")
    return findings
