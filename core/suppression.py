"""Suppression file loader — skip known-good findings before LLM triage.

Format (suppressions.yaml):
    - rule_id: python.lang.security.audit.sqli.raw-query-format-string
      reason: "Accepted risk — parameterized at call site"
    - file_glob: "tests/*"
      reason: "Test fixtures, not production code"
    - rule_id: B105
      file_glob: "config/*"
      reason: "Hardcoded token in config template, not a secret"

Rules:
  - ``rule_id`` alone suppresses every finding with that rule ID.
  - ``file_glob`` alone suppresses every finding whose file_path matches the glob.
  - Both fields together: finding must match BOTH to be suppressed (AND logic).
  - Suppressed findings get ``status = "suppressed"`` — they are NOT deleted.
"""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path
from typing import Any

from parsers.base import Finding

log = logging.getLogger(__name__)

_YAML_AVAILABLE = False
try:
    import yaml  # type: ignore[import-untyped]

    _YAML_AVAILABLE = True
except ImportError:
    pass


def _load_yaml(path: str) -> list[dict[str, Any]]:
    """Return parsed suppression rules from *path*.

    Falls back to a minimal line-by-line parser when PyYAML is absent so the
    tool stays dependency-free for simple ``rule_id``-only suppression files.
    """
    if _YAML_AVAILABLE:
        with open(path) as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, list):
            raise ValueError(f"suppressions.yaml must be a YAML list, got {type(data).__name__}")
        return data

    # Minimal fallback: parse ``- rule_id: X`` and ``  reason: Y`` lines only.
    rules: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    with open(path) as fh:
        for line in fh:
            stripped = line.strip()
            if stripped.startswith("- rule_id:"):
                if current:
                    rules.append(current)
                current = {"rule_id": stripped.split(":", 1)[1].strip()}
            elif stripped.startswith("rule_id:") and current:
                current["rule_id"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("file_glob:") and current:
                current["file_glob"] = stripped.split(":", 1)[1].strip().strip("\"'")
            elif stripped.startswith("reason:") and current:
                current["reason"] = stripped.split(":", 1)[1].strip().strip("\"'")
    if current:
        rules.append(current)
    return rules


def _matches(finding: Finding, rule: dict[str, Any]) -> bool:
    rule_id = rule.get("rule_id", "")
    file_glob = rule.get("file_glob", "")
    if rule_id and file_glob:
        return finding.rule_id == rule_id and fnmatch.fnmatch(finding.file_path, file_glob)
    if rule_id:
        return finding.rule_id == rule_id
    if file_glob:
        return fnmatch.fnmatch(finding.file_path, file_glob)
    return False


def apply_suppressions(findings: list[Finding], path: str) -> list[Finding]:
    """Mark findings matching suppression rules as ``status="suppressed"``.

    Suppressed findings are kept in the output so reviewers can audit what
    was skipped. Returns the same list (mutated in-place).
    """
    if not Path(path).exists():
        log.debug("No suppression file at %s — skipping", path)
        return findings

    rules = _load_yaml(path)
    log.info("Loaded %d suppression rule(s) from %s", len(rules), path)

    suppressed = 0
    for f in findings:
        for rule in rules:
            if _matches(f, rule):
                f.status = "suppressed"
                f.fp_reason = rule.get("reason", "suppressed by suppressions.yaml")
                suppressed += 1
                log.debug("Suppressed %s %s: %s", f.scanner, f.rule_id, f.fp_reason)
                break

    log.info("%d finding(s) suppressed", suppressed)
    return findings
