"""Self-contained HTML report — no external dependencies, single file output."""

from __future__ import annotations

from parsers.base import SEVERITY_ORDER, Finding

_SEVERITY_COLOR = {
    "critical": "#c0392b",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#95a5a6",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
h1 { padding: 24px 32px 8px; font-size: 1.5rem; border-bottom: 1px solid #30363d; }
h2 { font-size: 1.1rem; color: #8b949e; margin: 24px 32px 12px; text-transform: uppercase; letter-spacing: .05em; }
h3 { font-size: 1rem; margin-bottom: 6px; }
.meta { padding: 4px 32px 16px; color: #8b949e; font-size: .85rem; }
.summary { display: flex; gap: 16px; padding: 0 32px 24px; flex-wrap: wrap; }
.stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 20px; min-width: 120px; }
.stat .num { font-size: 2rem; font-weight: 700; }
.stat .label { font-size: .8rem; color: #8b949e; }
.sev-bar { display: flex; gap: 8px; padding: 0 32px 24px; flex-wrap: wrap; }
.sev-pill { border-radius: 4px; padding: 4px 12px; font-size: .85rem; font-weight: 600; color: #0d1117; }
table { width: calc(100% - 64px); margin: 0 32px 24px; border-collapse: collapse; font-size: .88rem; }
th { background: #161b22; color: #8b949e; text-align: left; padding: 8px 12px; border-bottom: 1px solid #30363d; }
td { padding: 8px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }
tr:hover td { background: #161b22; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .78rem; font-weight: 600; color: #0d1117; }
.details { margin: 0 32px 32px; display: grid; gap: 16px; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 18px 22px; }
.card-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.card-meta { font-size: .82rem; color: #8b949e; margin-bottom: 8px; }
.card-msg { font-size: .9rem; margin-bottom: 8px; }
.code { background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 10px 14px; font-family: 'Cascadia Code', monospace; font-size: .82rem; white-space: pre-wrap; overflow-x: auto; }
.tag { display: inline-block; background: #21262d; border-radius: 4px; padding: 1px 6px; font-size: .78rem; margin-right: 4px; }
.conf { font-size: .82rem; color: #8b949e; }
.section-suppressed { opacity: .6; }
"""


def _badge(severity: str) -> str:
    color = _SEVERITY_COLOR.get(severity.lower(), "#666")
    return f'<span class="badge" style="background:{color}">{severity.upper()}</span>'


def _sev_pill(severity: str, count: int) -> str:
    color = _SEVERITY_COLOR.get(severity.lower(), "#666")
    return f'<span class="sev-pill" style="background:{color}">{severity.upper()} {count}</span>'


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _summary_html(all_f: list[Finding], active: list[Finding], fp: list[Finding], sup: list[Finding]) -> str:
    by_sev: dict[str, int] = {}
    for f in active:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    pills = "".join(_sev_pill(s, by_sev[s]) for s in SEVERITY_ORDER if s in by_sev)
    return f"""
<div class="summary">
  <div class="stat"><div class="num">{len(all_f)}</div><div class="label">Total</div></div>
  <div class="stat"><div class="num">{len(active)}</div><div class="label">Active</div></div>
  <div class="stat"><div class="num">{len(fp)}</div><div class="label">Likely FP</div></div>
  <div class="stat"><div class="num">{len(sup)}</div><div class="label">Suppressed</div></div>
</div>
<div class="sev-bar">{pills}</div>
"""


def _findings_table_html(findings: list[Finding]) -> str:
    if not findings:
        return "<p style='padding:0 32px;color:#8b949e'>No active findings.</p>"

    rows = ""
    for f in findings:
        loc = _escape(f.file_path + (f":{f.line_number}" if f.line_number else ""))
        sources = f"×{len(f.sources)}" if len(f.sources) > 1 else ""
        conf = f"{f.confidence:.2f}" if f.confidence is not None else "—"
        cwe = f'<span class="tag">{_escape(f.cwe)}</span>' if f.cwe else ""
        rows += (
            f"<tr>"
            f"<td>{_badge(f.severity)}</td>"
            f"<td><code>{_escape(f.rule_id)}</code></td>"
            f"<td>{_escape(f.scanner)} {sources}</td>"
            f"<td>{_escape(f.title)} {cwe}</td>"
            f"<td><code>{loc}</code></td>"
            f"<td>{f.risk_score}</td>"
            f"<td>{conf}</td>"
            f"</tr>\n"
        )
    return f"""
<table>
  <thead><tr>
    <th>Severity</th><th>Rule</th><th>Scanners</th><th>Title</th>
    <th>Location</th><th>Risk Score</th><th>Confidence</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>"""


def _detail_cards_html(findings: list[Finding]) -> str:
    cards = ""
    for f in findings:
        loc = _escape(f.file_path + (f":{f.line_number}" if f.line_number else ""))
        sources_html = ""
        if len(f.sources) > 1:
            tags = "".join(f'<span class="tag">{_escape(s)}</span>' for s in f.sources)
            sources_html = f"<div>Reported by: {tags}</div>"
        cwe_html = f'<span class="tag">{_escape(f.cwe)}</span>' if f.cwe else ""
        snippet_html = (
            f'<div class="code">{_escape(f.code_snippet)}</div>' if f.code_snippet else ""
        )
        conf_html = f'<span class="conf">Confidence: {f.confidence:.2f}</span>' if f.confidence is not None else ""
        llm_html = (
            f'<div class="conf" style="margin-top:6px">LLM: {_escape(f.fp_reason)}</div>'
            if f.fp_reason
            else ""
        )
        cards += f"""
<div class="card">
  <div class="card-header">{_badge(f.severity)}<h3>{_escape(f.title)}</h3>{conf_html}</div>
  <div class="card-meta">
    <code>{_escape(f.rule_id)}</code> · {_escape(f.scanner)} · <code>{loc}</code>
    · Risk Score: {f.risk_score} {cwe_html}
  </div>
  {sources_html}
  <div class="card-msg">{_escape(f.message)}</div>
  {snippet_html}
  {llm_html}
</div>"""
    return f'<div class="details">{cards}</div>'


def _fp_table_html(findings: list[Finding]) -> str:
    rows = "".join(
        f"<tr><td>{_escape(f.scanner)}</td><td><code>{_escape(f.rule_id)}</code></td>"
        f"<td>{_escape(f.title)}</td><td>{_escape(f.fp_reason)}</td></tr>\n"
        for f in findings
    )
    return (
        "<table><thead><tr><th>Scanner</th><th>Rule</th><th>Title</th><th>Reason</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _suppressed_table_html(findings: list[Finding]) -> str:
    rows = "".join(
        f"<tr><td>{_escape(f.scanner)}</td><td><code>{_escape(f.rule_id)}</code></td>"
        f"<td>{_escape(f.title)}</td><td><code>{_escape(f.file_path)}</code></td>"
        f"<td>{_escape(f.fp_reason)}</td></tr>\n"
        for f in findings
    )
    return (
        "<table><thead><tr><th>Scanner</th><th>Rule</th><th>Title</th>"
        f"<th>Location</th><th>Reason</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def write_html(findings: list[Finding], path: str) -> None:
    """Write findings as a self-contained HTML report to path."""
    sorted_f = sorted(findings, key=lambda f: f.severity_rank)
    active = [f for f in sorted_f if f.status not in ("likely_fp", "suppressed")]
    fp = [f for f in sorted_f if f.status == "likely_fp"]
    suppressed = [f for f in sorted_f if f.status == "suppressed"]

    body = _summary_html(findings, active, fp, suppressed)
    body += "<h2>Active Findings</h2>"
    body += _findings_table_html(active)
    body += "<h2>Details</h2>"
    body += _detail_cards_html(active)

    if fp:
        body += "<h2>Filtered False Positives</h2>"
        body += _fp_table_html(fp)

    if suppressed:
        body += '<h2 class="section-suppressed">Suppressed</h2>'
        body += _suppressed_table_html(suppressed)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SAST+DAST Triage Report</title>
<style>{_CSS}</style>
</head>
<body>
<h1>SAST+DAST Triage Report</h1>
<p class="meta">{len(findings)} total findings · {len(active)} active · {len(fp)} likely FP · {len(suppressed)} suppressed</p>
{body}
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
