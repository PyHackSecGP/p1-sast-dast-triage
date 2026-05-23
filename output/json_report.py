"""JSON report output."""
from __future__ import annotations

import json
from dataclasses import asdict

from parsers.base import Finding


def write_json(findings: list[Finding], path: str) -> None:
    """Write findings as a JSON report to path."""
    data = {
        "total": len(findings),
        "by_severity": _count_by_severity(findings),
        "findings": [_finding_dict(f) for f in sorted(findings, key=lambda f: f.severity_rank)],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)


def _finding_dict(f: Finding) -> dict:
    d = asdict(f)
    d["id"] = f.id
    d.pop("raw", None)   # raw scanner output bloats the report
    return d


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
