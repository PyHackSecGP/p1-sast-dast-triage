#!/usr/bin/env python3
"""Regenerate committed golden report files from the fixture data.

Run after intentionally changing report output. Diff before committing:
    python3 scripts/update_goldens.py
    git diff tests/golden/
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.dedup import deduplicate  # noqa: E402
from core.scorer import assign_risk_score  # noqa: E402
from output.markdown_report import write_markdown  # noqa: E402
from output.sarif_report import write_sarif  # noqa: E402
from parsers import (  # noqa: E402
    BanditParser,
    NucleiParser,
    SemgrepParser,
    TrivyParser,
    ZapParser,
)

FIXTURES = os.path.join(ROOT, "tests", "fixtures")
GOLDEN = os.path.join(ROOT, "tests", "golden")


def main() -> None:
    os.makedirs(GOLDEN, exist_ok=True)

    findings: list = []
    findings += SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    findings += BanditParser().parse(f"{FIXTURES}/bandit_sample.json")
    findings += ZapParser().parse(f"{FIXTURES}/zap_sample.xml")
    findings += TrivyParser().parse(f"{FIXTURES}/trivy_sample.json")
    findings += NucleiParser().parse(f"{FIXTURES}/nuclei_sample.jsonl")
    findings = deduplicate(findings)
    findings = assign_risk_score(findings)

    write_markdown(findings, os.path.join(GOLDEN, "expected.md"))
    write_sarif(findings, os.path.join(GOLDEN, "expected.sarif"))
    print(f"Wrote goldens for {len(findings)} findings to {GOLDEN}")


if __name__ == "__main__":
    main()
