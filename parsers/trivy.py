"""Trivy JSON output parser (container image, filesystem, IaC scans)."""
from __future__ import annotations

import json

from .base import BaseParser, Finding


class TrivyParser(BaseParser):
    """Parse output from: trivy image --format json --output results.json <image>
    Also handles: trivy fs, trivy config, trivy repo output.
    """

    def parse(self, path: str) -> list[Finding]:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        findings = []
        results = data.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            result_type = result.get("Type", "")

            # Vulnerabilities (CVE findings from packages)
            for vuln in result.get("Vulnerabilities", []) or []:
                severity = self._normalize_severity(vuln.get("Severity", "UNKNOWN"))
                cve_id = vuln.get("VulnerabilityID", "")
                pkg = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")

                # CWE from CVSS data
                cwe = ""
                for _, cvss_data in (vuln.get("CVSS") or {}).items():
                    if isinstance(cvss_data, dict):
                        break
                cwe_list = vuln.get("CweIDs", []) or []
                if cwe_list:
                    cwe = cwe_list[0].replace("CWE-", "")

                msg = vuln.get("Description", "").strip()
                if fixed:
                    msg += f" Fixed in: {fixed}."

                findings.append(Finding(
                    scanner="trivy",
                    rule_id=cve_id or vuln.get("VulnerabilityID", "unknown"),
                    title=f"{cve_id}: {pkg} {installed}",
                    severity=severity,
                    message=msg,
                    file_path=target,
                    line_number=0,
                    cwe=cwe,
                    tags=[result_type, pkg] + (vuln.get("References", [])[:1]),
                    raw=vuln,
                ))

            # Misconfigurations (IaC / config findings)
            for misconf in result.get("Misconfigurations", []) or []:
                severity = self._normalize_severity(misconf.get("Severity", "LOW"))
                check_id = misconf.get("ID", "unknown")
                cwe_list = misconf.get("CWEs", []) or []
                cwe = cwe_list[0].replace("CWE-", "") if cwe_list else ""

                findings.append(Finding(
                    scanner="trivy",
                    rule_id=check_id,
                    title=misconf.get("Title", check_id),
                    severity=severity,
                    message=misconf.get("Description", "").strip(),
                    file_path=target,
                    line_number=misconf.get("StartLine", 0),
                    cwe=cwe,
                    tags=[result_type, misconf.get("Type", "")],
                    raw=misconf,
                ))

            # Secrets
            for secret in result.get("Secrets", []) or []:
                findings.append(Finding(
                    scanner="trivy",
                    rule_id=secret.get("RuleID", "secret"),
                    title=secret.get("Title", "Secret detected"),
                    severity="high",
                    message=secret.get("Match", "").strip(),
                    file_path=target,
                    line_number=secret.get("StartLine", 0),
                    cwe="798",
                    tags=["secret", secret.get("Category", "")],
                    raw=secret,
                ))

        return findings
