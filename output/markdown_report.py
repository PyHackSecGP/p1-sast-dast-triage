"""Markdown report output."""
from __future__ import annotations

from parsers.base import Finding, SEVERITY_ORDER

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def write_markdown(findings: list[Finding], path: str) -> None:
    """Write findings as a Markdown report to path."""
    sorted_findings = sorted(findings, key=lambda f: f.severity_rank)
    true_positives = [f for f in sorted_findings if f.false_positive is not True]
    false_positives = [f for f in sorted_findings if f.false_positive is True]

    lines = [
        "# SAST+DAST Triage Report\n",
        _summary_section(findings, true_positives, false_positives),
        _findings_table(true_positives),
    ]
    if false_positives:
        lines.append(_fp_section(false_positives))

    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def _summary_section(all_f, tp, fp) -> str:
    counts = {}
    for f in tp:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    rows = "\n".join(
        f"| {sev.title()} | {_SEVERITY_EMOJI.get(sev, '')} | {counts.get(sev, 0)} |"
        for sev in SEVERITY_ORDER
    )
    return (
        f"## Summary\n\n"
        f"| Metric | Value |\n|---|---|\n"
        f"| Total findings | {len(all_f)} |\n"
        f"| True positives | {len(tp)} |\n"
        f"| False positives filtered | {len(fp)} |\n\n"
        f"### By Severity (true positives)\n\n"
        f"| Severity | | Count |\n|---|---|---|\n{rows}\n"
    )


def _findings_table(findings: list[Finding]) -> str:
    if not findings:
        return "## Findings\n\nNo true positive findings.\n"

    rows = []
    for f in findings:
        fp_label = ""
        if f.false_positive is None:
            fp_label = "⚠ unreviewed"
        loc = f.file_path + (f":{f.line_number}" if f.line_number else "")
        rows.append(
            f"| {_SEVERITY_EMOJI.get(f.severity, '')} {f.severity.upper()} "
            f"| `{f.rule_id}` | {f.scanner} | {f.title} "
            f"| `{loc}` | {f.cvss_score} | {fp_label} |"
        )

    header = (
        "## Findings\n\n"
        "| Severity | Rule | Scanner | Title | Location | CVSS | Notes |\n"
        "|---|---|---|---|---|---|---|\n"
    )
    detail_sections = "\n\n".join(_finding_detail(f) for f in findings)
    return header + "\n".join(rows) + "\n\n---\n\n" + detail_sections


def _finding_detail(f: Finding) -> str:
    loc = f.file_path + (f":{f.line_number}" if f.line_number else "")
    lines = [
        f"### {_SEVERITY_EMOJI.get(f.severity, '')} {f.title}",
        f"**Scanner:** {f.scanner} | **Rule:** `{f.rule_id}` | "
        f"**Severity:** {f.severity.upper()} | **CVSS:** {f.cvss_score}",
        f"**Location:** `{loc}`",
        "",
        f.message,
    ]
    if f.cwe:
        lines.append(f"\n**CWE:** {f.cwe}")
    if f.code_snippet:
        lines.append(f"\n```\n{f.code_snippet}\n```")
    if f.fp_reason:
        lines.append(f"\n**LLM note:** {f.fp_reason}")
    return "\n".join(lines)


def _fp_section(findings: list[Finding]) -> str:
    rows = "\n".join(
        f"| {f.scanner} | `{f.rule_id}` | {f.title} | {f.fp_reason} |"
        for f in findings
    )
    return (
        "## Filtered False Positives\n\n"
        "| Scanner | Rule | Title | Reason |\n|---|---|---|---|\n"
        + rows + "\n"
    )
