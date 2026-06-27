"""CWE-based heuristic risk score assignment for normalized findings."""
from __future__ import annotations

from parsers.base import Finding

# Baseline risk scores per severity level — CWE-based heuristic, 0-10 scale.
_SEVERITY_RISK: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}

# CWE nudges: bump score up if CWE implies higher exploitability.
_CWE_BUMPS: dict[str, float] = {
    "CWE-89": 1.0,   # SQL injection
    "CWE-79": 0.5,   # XSS
    "CWE-78": 1.0,   # OS command injection
    "CWE-22": 0.5,   # path traversal
    "CWE-94": 1.0,   # code injection
    "CWE-502": 0.75, # deserialization
    "CWE-287": 0.75, # improper authentication
    "CWE-798": 1.0,  # hardcoded credentials
}


def assign_risk_score(findings: list[Finding]) -> list[Finding]:
    """Assign risk_score to each finding in-place and return the list."""
    for f in findings:
        base = _SEVERITY_RISK.get(f.severity.lower(), 0.0)
        bump = _CWE_BUMPS.get(f.cwe, 0.0)
        f.risk_score = min(10.0, round(base + bump, 1))
    return findings
