"""SARIF 2.1.0 report output for GitHub code scanning integration."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from parsers.base import Finding

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}

_SEVERITY_TO_RANK = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """Deduplicate rules from findings for the tool component."""
    seen: set[str] = set()
    rules = []
    for f in findings:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        rule: dict[str, Any] = {
            "id": f.rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "defaultConfiguration": {
                "level": _SEVERITY_TO_LEVEL.get(f.severity.lower(), "warning"),
            },
            "properties": {
                "tags": f.tags or [],
                "security-severity": str(f.risk_score),
            },
        }
        if f.cwe:
            rule["relationships"] = [
                {
                    "target": {
                        "id": f.cwe,
                        "toolComponent": {"name": "CWE"},
                    },
                    "kinds": ["superset"],
                }
            ]
        rules.append(rule)
    return rules


def _build_results(findings: list[Finding]) -> list[dict[str, Any]]:
    """Convert findings to SARIF result objects."""
    results = []
    for f in findings:
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": _SEVERITY_TO_LEVEL.get(f.severity.lower(), "warning"),
            "message": {"text": f.message or f.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": max(1, f.line_number or 1)},
                    }
                }
            ],
            "rank": _SEVERITY_TO_RANK.get(f.severity.lower(), 0.0),
            "properties": {
                "scanner": f.scanner,
                "status": f.status,
                "risk_score": f.risk_score,
            },
        }
        if f.cwe:
            result["taxa"] = [{"id": f.cwe, "toolComponent": {"name": "CWE"}}]
        if f.code_snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": f.code_snippet
            }
        if f.status == "likely_fp":
            result["suppressions"] = [
                {"kind": "inSource", "justification": f.fp_reason or "LLM flagged as likely false positive"}
            ]
        results.append(result)
    return results


def write_sarif(findings: list[Finding], path: str, tool_name: str = "sast-dast-triage") -> None:
    """Write findings as SARIF 2.1.0 to path."""
    sarif_doc: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "1.0.0",
                        "informationUri": "https://github.com/gpsingh/p1-sast-dast-triage",
                        "rules": _build_rules(findings),
                    }
                },
                "results": _build_results(findings),
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                ],
            }
        ],
    }
    with open(path, "w") as fh:
        json.dump(sarif_doc, fh, indent=2)
