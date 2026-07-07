"""Semgrep JSON output parser."""

from __future__ import annotations

import json

from .base import BaseParser, Finding, normalize_cwe


class SemgrepParser(BaseParser):
    """Parse output from: semgrep --json --output results.json ."""

    def parse(self, path: str) -> list[Finding]:
        with open(path) as f:
            data = json.load(f)

        findings = []
        for result in data.get("results", []):
            extra = result.get("extra", {})
            meta = extra.get("metadata", {})

            severity = self._normalize_severity(extra.get("severity", "info"))
            cwe = normalize_cwe(meta.get("cwe", ""))

            findings.append(
                Finding(
                    scanner="semgrep",
                    rule_id=result.get("check_id", "unknown"),
                    title=result.get("check_id", "unknown").split(".")[-1],
                    severity=severity,
                    message=extra.get("message", "").strip(),
                    file_path=result.get("path", ""),
                    line_number=result.get("start", {}).get("line", 0),
                    code_snippet=extra.get("lines", "").strip(),
                    cwe=cwe,
                    tags=meta.get("tags", []),
                    raw=result,
                )
            )
        return findings
