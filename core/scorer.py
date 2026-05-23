"""CVSS v3.1 base score assignment for normalized findings."""
from __future__ import annotations

from parsers.base import Finding

# Baseline CVSS scores per severity level — conservative defaults.
# Real CVSS requires all 8 metrics; these are triage approximations.
_SEVERITY_CVSS: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}

# CWE-to-CVSS nudges: bump score up if CWE implies higher exploitability.
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


def assign_cvss(findings: list[Finding]) -> list[Finding]:
    """Assign cvss_score to each finding in-place and return the list."""
    for f in findings:
        base = _SEVERITY_CVSS.get(f.severity.lower(), 0.0)
        bump = _CWE_BUMPS.get(f.cwe, 0.0)
        f.cvss_score = min(10.0, round(base + bump, 1))
    return findings
