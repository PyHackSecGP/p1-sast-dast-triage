"""LLM-powered false positive filter using a local Ollama endpoint."""

from __future__ import annotations

import json
import logging
import os
import socket
import urllib.error
import urllib.request
from typing import Any

from parsers.base import Finding

log = logging.getLogger(__name__)

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_URL = f"{OLLAMA_HOST}/api/generate"
MODEL = os.environ.get("TRIAGE_MODEL", "llama3.2:3b")  # 3B stays loaded between calls
TIMEOUT = 300

_SYSTEM = (
    "You are a senior application security engineer reviewing SAST/DAST scanner findings. "
    "Classify each finding as a true positive or false positive and rate your confidence. "
    "Respond ONLY with a JSON object: "
    '{"verdict": "true_positive" | "false_positive", "confidence": <float 0.0-1.0>, "reason": "<one sentence>"}'
)


def _extract_json(text: str) -> dict[str, Any]:
    """Extract the first valid JSON object from model output.

    Small models (llama3.2:3b) frequently wrap JSON in prose or emit a
    naked comment when they refuse to classify. Raise ``ValueError`` for
    every unrecoverable case so callers can leave findings unreviewed
    rather than crashing the pipeline.
    """
    if not text:
        raise ValueError("Empty response from model")
    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object in response")
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                parsed: dict[str, Any] = json.loads(text[start : i + 1])
                return parsed
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


def _query_ollama(prompt: str) -> dict[str, Any]:
    model = os.environ.get("TRIAGE_MODEL", MODEL)
    payload = json.dumps(
        {
            "model": model,
            "prompt": f"{_SYSTEM}\n\n{prompt}",
            "stream": False,
        }
    ).encode()

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
            response: dict[str, Any] = json.loads(resp.read())
            return response
    finally:
        socket.setdefaulttimeout(prev)


def filter_false_positives(
    findings: list[Finding],
    verbose: bool = False,
) -> list[Finding]:
    """Run each finding through the local LLM and tag false positives.

    Findings that fail the LLM call are left unreviewed (false_positive=None)
    rather than dropped, so the user can still see them.
    """
    # ``verbose`` remains as a parameter for API back-compat, but per-finding
    # progress now flows through the logging module. Callers wanting the old
    # streaming output should configure the ``core.llm`` logger at DEBUG.
    del verbose
    total = len(findings)
    for i, f in enumerate(findings, 1):
        log.debug("[%d/%d] %s: %s", i, total, f.scanner, f.title[:60])
        try:
            result = _query_ollama(_build_prompt(f))
            response_text = result.get("response", "")
            verdict_data = _extract_json(response_text)
            verdict = verdict_data.get("verdict")
            if verdict not in ("true_positive", "false_positive"):
                raise ValueError(f"Missing/invalid verdict field: {verdict!r}")
            is_fp = verdict == "false_positive"
            f.false_positive = is_fp
            f.fp_reason = verdict_data.get("reason", "")
            f.status = "likely_fp" if is_fp else "confirmed"
            raw_conf = verdict_data.get("confidence")
            if raw_conf is not None:
                try:
                    f.confidence = round(max(0.0, min(1.0, float(raw_conf))), 2)
                except (TypeError, ValueError):
                    pass
            log.debug(
                "  -> %s (conf=%.2f): %s",
                "FP" if is_fp else "TP",
                f.confidence if f.confidence is not None else 0.0,
                f.fp_reason[:60],
            )
        except (
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
            ValueError,
            KeyError,
        ) as e:
            # LLM never produced a usable verdict — mark unreviewed rather
            # than leaving the default "confirmed", which would falsely
            # imply a human/model looked at it.
            f.status = "unreviewed"
            f.fp_reason = f"llm_error: {e}"
            log.warning("skip finding %s (llm error: %s)", f.id, e)
    return findings
