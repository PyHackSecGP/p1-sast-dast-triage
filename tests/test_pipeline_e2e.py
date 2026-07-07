"""End-to-end pipeline tests against committed golden output files.

Runs parse -> dedupe -> score -> write on the combined fixture data and
compares the emitted Markdown / SARIF against golden files. If the pipeline
changes intentionally, regenerate the goldens via ``scripts/update_goldens.py``.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.dedup import deduplicate
from core.scorer import assign_risk_score
from output.markdown_report import write_markdown
from output.sarif_report import write_sarif
from parsers import BanditParser, NucleiParser, SemgrepParser, TrivyParser, ZapParser

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
GOLDEN = os.path.join(os.path.dirname(__file__), "golden")


def _run_pipeline() -> list:
    findings: list = []
    findings += SemgrepParser().parse(f"{FIXTURES}/semgrep_sample.json")
    findings += BanditParser().parse(f"{FIXTURES}/bandit_sample.json")
    findings += ZapParser().parse(f"{FIXTURES}/zap_sample.xml")
    findings += TrivyParser().parse(f"{FIXTURES}/trivy_sample.json")
    findings += NucleiParser().parse(f"{FIXTURES}/nuclei_sample.jsonl")
    findings = deduplicate(findings)
    return assign_risk_score(findings)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.parametrize(
    "writer,ext",
    [(write_markdown, "md"), (write_sarif, "sarif")],
)
def test_pipeline_matches_golden(tmp_path, writer, ext) -> None:
    findings = _run_pipeline()
    out = tmp_path / f"actual.{ext}"
    writer(findings, str(out))

    golden = os.path.join(GOLDEN, f"expected.{ext}")
    if not os.path.exists(golden):
        pytest.skip(f"Golden missing: {golden}. Run scripts/update_goldens.py.")

    expected = _read(golden)
    actual = out.read_text(encoding="utf-8")

    if ext == "sarif":
        # SARIF has a runtime timestamp — compare structure minus invocations.
        expected_doc = json.loads(expected)
        actual_doc = json.loads(actual)
        for doc in (expected_doc, actual_doc):
            for run in doc.get("runs", []):
                run.pop("invocations", None)
        assert actual_doc == expected_doc
    else:
        assert actual == expected, (
            "Golden mismatch. Regenerate with scripts/update_goldens.py "
            "or diff manually."
        )


def test_pipeline_shape() -> None:
    """Basic invariants without needing goldens."""
    findings = _run_pipeline()
    # Every finding has a canonical severity + non-empty sources.
    from parsers.base import BaseParser
    for f in findings:
        assert f.severity in BaseParser.CANONICAL_SEVERITIES
        assert f.sources
        assert 0.0 <= f.risk_score <= 10.0
