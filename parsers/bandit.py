"""Bandit JSON output parser."""
from __future__ import annotations

import json

from .base import BaseParser, Finding


class BanditParser(BaseParser):
    """Parse output from: bandit -r . -f json -o results.json"""

    def parse(self, path: str) -> list[Finding]:
        with open(path) as f:
            data = json.load(f)

        findings = []
        for issue in data.get("results", []):
            # Bandit reports severity and confidence separately; we use severity.
            severity = self._normalize_severity(issue.get("issue_severity", "LOW"))

            findings.append(Finding(
                scanner="bandit",
                rule_id=issue.get("test_id", "unknown"),
                title=issue.get("test_name", "unknown"),
                severity=severity,
                message=issue.get("issue_text", "").strip(),
                file_path=issue.get("filename", ""),
                line_number=issue.get("line_number", 0),
                code_snippet=issue.get("code", "").strip(),
                cwe=issue.get("issue_cwe", {}).get("id", ""),
                tags=[issue.get("test_name", "")],
                raw=issue,
            ))
        return findings
