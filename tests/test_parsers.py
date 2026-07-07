"""Tests for scanner output parsers — one per supported scanner."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers import BanditParser, NucleiParser, SemgrepParser, TrivyParser, ZapParser

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# ── Semgrep ───────────────────────────────────────────────────────────────────

def test_semgrep_parser() -> None:
    findings = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    assert len(findings) == 2
    sqli = findings[0]
    assert sqli.scanner == "semgrep"
    assert sqli.severity == "high"
    assert sqli.cwe == "CWE-89"
    assert sqli.line_number == 42
    assert sqli.file_path == "app/db.py"
    assert sqli.sources == ["semgrep:" + sqli.rule_id]


# ── Bandit ────────────────────────────────────────────────────────────────────

def test_bandit_parser() -> None:
    findings = BanditParser().parse(f"{FIXTURES}/bandit_sample.json")
    assert len(findings) == 2
    sqli = findings[0]
    assert sqli.scanner == "bandit"
    assert sqli.severity == "high"
    assert sqli.rule_id == "B608"
    assert sqli.line_number == 42
    assert sqli.cwe == "CWE-89"


# ── ZAP ───────────────────────────────────────────────────────────────────────

def test_zap_parser() -> None:
    findings = ZapParser().parse(f"{FIXTURES}/zap_sample.xml")
    assert len(findings) == 2
    xss = findings[0]
    assert xss.scanner == "zap"
    assert xss.severity == "high"
    assert xss.cwe == "CWE-79"


# ── Trivy ─────────────────────────────────────────────────────────────────────

def test_trivy_parser_covers_vuln_misconfig_secret() -> None:
    """Real Trivy output mixes three finding classes in the same file."""
    findings = TrivyParser().parse(f"{FIXTURES}/trivy_sample.json")
    # 2 vulns + 1 misconfig + 1 secret
    assert len(findings) == 4

    by_rule = {f.rule_id: f for f in findings}
    # CVE vulnerability
    cve = by_rule["CVE-2023-52425"]
    assert cve.scanner == "trivy"
    assert cve.severity == "high"
    assert cve.cwe == "CWE-611"
    # Critical CVE
    assert by_rule["CVE-2022-1000"].severity == "critical"
    # Misconfig with StartLine
    misconf = by_rule["DS002"]
    assert misconf.line_number == 12
    assert misconf.cwe == "CWE-250"
    # Secret is canonicalized to CWE-798
    secret = by_rule["aws-access-key-id"]
    assert secret.cwe == "CWE-798"
    assert secret.severity == "high"


# ── Nuclei ────────────────────────────────────────────────────────────────────

def test_nuclei_parser_jsonl() -> None:
    findings = NucleiParser().parse(f"{FIXTURES}/nuclei_sample.jsonl")
    assert len(findings) == 3

    by_rule = {f.rule_id: f for f in findings}
    high = by_rule["CVE-2022-0778"]
    assert high.scanner == "nuclei"
    assert high.severity == "high"
    assert high.cwe == "CWE-835"

    info = by_rule["wordpress-detect"]
    assert info.severity == "info"
    assert info.cwe == ""  # empty classification list

    exposure = by_rule["git-config"]
    assert exposure.severity == "medium"
    assert exposure.cwe == "CWE-538"


# ── Cross-parser invariants ───────────────────────────────────────────────────

def test_finding_id_stability() -> None:
    """Same rule+file+line should always produce the same ID."""
    a = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    b = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    assert a[0].id == b[0].id


def test_every_parser_seeds_sources() -> None:
    """No parser should emit a Finding with an empty sources list."""
    parsers_and_fixtures = [
        (SemgrepParser(), "semgrep_sample.json"),
        (BanditParser(), "bandit_sample.json"),
        (ZapParser(), "zap_sample.xml"),
        (TrivyParser(), "trivy_sample.json"),
        (NucleiParser(), "nuclei_sample.jsonl"),
    ]
    for parser, fixture in parsers_and_fixtures:
        findings = parser.parse(f"{FIXTURES}/{fixture}")
        for f in findings:
            assert f.sources, f"{type(parser).__name__} produced finding without sources"
            assert f.sources[0].startswith(f.scanner + ":"), (
                f"sources not seeded with '<scanner>:<rule_id>' — got {f.sources[0]!r}"
            )


def test_every_parser_produces_canonical_severity() -> None:
    from parsers.base import BaseParser
    parsers_and_fixtures = [
        (SemgrepParser(), "semgrep_sample.json"),
        (BanditParser(), "bandit_sample.json"),
        (ZapParser(), "zap_sample.xml"),
        (TrivyParser(), "trivy_sample.json"),
        (NucleiParser(), "nuclei_sample.jsonl"),
    ]
    for parser, fixture in parsers_and_fixtures:
        findings = parser.parse(f"{FIXTURES}/{fixture}")
        for f in findings:
            assert f.severity in BaseParser.CANONICAL_SEVERITIES, (
                f"{type(parser).__name__} emitted non-canonical severity {f.severity!r}"
            )
