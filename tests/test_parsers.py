"""Tests for scanner output parsers."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from parsers import SemgrepParser, BanditParser, ZapParser

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_semgrep_parser():
    findings = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    assert len(findings) == 2
    sqli = findings[0]
    assert sqli.scanner == "semgrep"
    assert sqli.severity == "high"
    assert "CWE-89" in sqli.cwe
    assert sqli.line_number == 42
    assert sqli.file_path == "app/db.py"
    print(f"  semgrep: {len(findings)} findings OK")


def test_bandit_parser():
    findings = BanditParser().parse(f"{FIXTURES}/bandit_sample.json")
    assert len(findings) == 2
    sqli = findings[0]
    assert sqli.scanner == "bandit"
    assert sqli.severity == "high"
    assert sqli.rule_id == "B608"
    assert sqli.line_number == 42
    print(f"  bandit: {len(findings)} findings OK")


def test_zap_parser():
    findings = ZapParser().parse(f"{FIXTURES}/zap_sample.xml")
    assert len(findings) == 2
    xss = findings[0]
    assert xss.scanner == "zap"
    assert xss.severity == "high"
    assert "79" in xss.cwe
    print(f"  zap: {len(findings)} findings OK")


def test_finding_id_stability():
    """Same rule+file+line should always produce the same ID."""
    findings1 = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    findings2 = SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    assert findings1[0].id == findings2[0].id
    print("  finding ID stability OK")


if __name__ == "__main__":
    test_semgrep_parser()
    test_bandit_parser()
    test_zap_parser()
    test_finding_id_stability()
    print("\nAll parser tests passed.")
