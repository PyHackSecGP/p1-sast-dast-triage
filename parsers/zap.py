"""OWASP ZAP XML output parser."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .base import BaseParser, Finding


class ZapParser(BaseParser):
    """Parse output from: zap.sh -cmd -quickurl <url> -quickout results.xml"""

    def parse(self, path: str) -> list[Finding]:
        tree = ET.parse(path)
        root = tree.getroot()

        findings = []
        # ZAP XML structure: <OWASPZAPReport><site><alerts><alertitem>
        for alert in root.iter("alertitem"):
            risk_code = alert.findtext("riskcode", "0")
            severity = self._normalize_severity(risk_code)

            rule_id = alert.findtext("pluginid", "unknown")
            title = alert.findtext("alert", "unknown")
            cwe_id = alert.findtext("cweid", "")
            cwe = f"CWE-{cwe_id}" if cwe_id else ""

            # One finding per affected URL instance
            for instance in alert.findall(".//instance"):
                uri = instance.findtext("uri", "")
                method = instance.findtext("method", "")
                evidence = instance.findtext("evidence", "")

                findings.append(Finding(
                    scanner="zap",
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    message=f"{alert.findtext('desc', '').strip()} {alert.findtext('solution', '').strip()}".strip(),
                    file_path=uri,
                    line_number=0,
                    url=uri,
                    code_snippet=f"{method} {uri}\nEvidence: {evidence}".strip() if evidence else "",
                    cwe=cwe,
                    tags=[alert.findtext("wascid", "")],
                    raw={"pluginid": rule_id, "uri": uri, "method": method},
                ))

            # If no instances, emit one finding for the alert itself
            if not alert.findall(".//instance"):
                uri = alert.findtext("url", "")
                findings.append(Finding(
                    scanner="zap",
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    message=alert.findtext("desc", "").strip(),
                    file_path=uri,
                    line_number=0,
                    url=uri,
                    cwe=cwe,
                    tags=[alert.findtext("wascid", "")],
                    raw={"pluginid": rule_id, "uri": uri},
                ))

        return findings
