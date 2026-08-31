"""Markdown report output."""

from __future__ import annotations

from parsers.base import SEVERITY_ORDER, Finding

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
    active = [f for f in sorted_findings if f.status not in ("likely_fp", "suppressed")]
    false_positives = [f for f in sorted_findings if f.status == "likely_fp"]
    suppressed = [f for f in sorted_findings if f.status == "suppressed"]

    lines = [
        "# SAST+DAST Triage Report\n",
        _summary_section(findings, active, false_positives, suppressed),
        _findings_table(active),
    ]
    if false_positives:
        lines.append(_fp_section(false_positives))
    if suppressed:
        lines.append(_suppressed_section(suppressed))

    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def _summary_section(all_f, tp, fp, suppressed) -> str:
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
        f"| Active (needs review) | {len(tp)} |\n"
        f"| False positives filtered | {len(fp)} |\n"
        f"| Suppressed | {len(suppressed)} |\n\n"
        f"### By Severity (true positives)\n\n"
        f"| Severity | | Count |\n|---|---|---|\n{rows}\n"
    )


def _findings_table(findings: list[Finding]) -> str:
    if not findings:
        return "## Findings\n\nNo true positive findings.\n"

    rows = []
    for f in findings:
        notes = ""
        if f.false_positive is None:
            notes = "⚠ unreviewed"
        conf_label = f"{f.confidence:.2f}" if f.confidence is not None else "—"
        loc = f.file_path + (f":{f.line_number}" if f.line_number else "")
        sources_label = f"x{len(f.sources)}" if len(f.sources) > 1 else ""
        rows.append(
            f"| {_SEVERITY_EMOJI.get(f.severity, '')} {f.severity.upper()} "
            f"| `{f.rule_id}` | {f.scanner} {sources_label} | {f.title} "
            f"| `{loc}` | {f.risk_score} | {conf_label} | {notes} |"
        )

    header = (
        "## Findings\n\n"
        "| Severity | Rule | Scanners | Title | Location | Risk Score | Confidence | Notes |\n"
        "|---|---|---|---|---|---|---|---|\n"
    )
    detail_sections = "\n\n".join(_finding_detail(f) for f in findings)
    return header + "\n".join(rows) + "\n\n---\n\n" + detail_sections


def _finding_detail(f: Finding) -> str:
    loc = f.file_path + (f":{f.line_number}" if f.line_number else "")
    lines = [
        f"### {_SEVERITY_EMOJI.get(f.severity, '')} {f.title}",
        f"**Scanner:** {f.scanner} | **Rule:** `{f.rule_id}` | "
        f"**Severity:** {f.severity.upper()} | **Risk Score:** {f.risk_score}",
        f"**Location:** `{loc}`",
    ]
    if len(f.sources) > 1:
        lines.append(f"**Reported by:** {', '.join(f'`{s}`' for s in f.sources)}")
    lines += ["", f.message]
    if f.cwe:
        lines.append(f"\n**CWE:** {f.cwe}")
    if f.code_snippet:
        lines.append(f"\n```\n{f.code_snippet}\n```")
    if f.confidence is not None:
        lines.append(f"\n**LLM confidence:** {f.confidence:.2f}")
    if f.fp_reason:
        lines.append(f"**LLM note:** {f.fp_reason}")
    return "\n".join(lines)


def _fp_section(findings: list[Finding]) -> str:
    rows = "\n".join(
        f"| {f.scanner} | `{f.rule_id}` | {f.title} | {f.fp_reason} |" for f in findings
    )
    return (
        "## Filtered False Positives\n\n"
        "| Scanner | Rule | Title | Reason |\n|---|---|---|---|\n" + rows + "\n"
    )


def _suppressed_section(findings: list[Finding]) -> str:
    rows = "\n".join(
        f"| {f.scanner} | `{f.rule_id}` | {f.title} | `{f.file_path}` | {f.fp_reason} |"
        for f in findings
    )
    return (
        "## Suppressed Findings\n\n"
        "_These findings matched suppressions.yaml rules and were not sent to LLM triage._\n\n"
        "| Scanner | Rule | Title | Location | Reason |\n|---|---|---|---|---|\n" + rows + "\n"
    )
