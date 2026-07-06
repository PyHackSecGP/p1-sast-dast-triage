"""Nuclei JSON/JSONL output parser."""
from __future__ import annotations

import json

from .base import BaseParser, Finding, normalize_cwe


class NucleiParser(BaseParser):
    """Parse output from: nuclei -jsonl -o results.jsonl
    Also accepts a single-JSON array: nuclei -json -o results.json
    """

    def parse(self, path: str) -> list[Finding]:
        findings = []
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read().strip()

        # Detect JSONL vs single JSON array
        if content.startswith("["):
            records = json.loads(content)
        else:
            records = [json.loads(line) for line in content.splitlines() if line.strip()]

        for rec in records:
            info = rec.get("info", {})
            severity = self._normalize_severity(info.get("severity", "info"))

            cwe = normalize_cwe(info.get("classification", {}).get("cwe-id", ""))

            # Host + matched-at give us the URL; extract a pseudo file_path
            matched_at = rec.get("matched-at", rec.get("host", ""))
            template_id = rec.get("template-id", "unknown")

            findings.append(Finding(
                scanner="nuclei",
                rule_id=template_id,
                title=info.get("name", template_id),
                severity=severity,
                message=rec.get("matcher-name", info.get("description", "")).strip(),
                file_path=matched_at,
                line_number=0,
                url=matched_at,
                cwe=cwe,
                tags=info.get("tags", []) if isinstance(info.get("tags"), list)
                     else [t.strip() for t in str(info.get("tags", "")).split(",") if t.strip()],
                raw=rec,
            ))
        return findings
