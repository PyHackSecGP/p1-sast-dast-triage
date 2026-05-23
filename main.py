"""SAST+DAST Triage Tool — CLI entry point."""
from __future__ import annotations

import argparse
import sys

from parsers import PARSERS
from core import deduplicate, assign_cvss, filter_false_positives
from output import write_json, write_markdown


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Triage SAST/DAST scanner output: deduplicate, score, filter false positives.",
    )
    p.add_argument("--input", "-i", required=True, help="Path to scanner output file")
    p.add_argument(
        "--scanner", "-s", required=True, choices=list(PARSERS),
        help="Scanner that produced the output (semgrep | bandit | zap)",
    )
    p.add_argument(
        "--output", "-o", default="report",
        help="Output file path without extension (default: report)",
    )
    p.add_argument(
        "--format", "-f", choices=["json", "markdown", "both"], default="both",
        help="Output format (default: both)",
    )
    p.add_argument(
        "--llm", action="store_true",
        help="Run LLM false-positive filter via claw-core (slower)",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args()


def main() -> None:
    """Run the triage pipeline."""
    args = parse_args()

    if args.verbose:
        print(f"[+] Parsing {args.scanner} output from {args.input}")

    parser = PARSERS[args.scanner]()
    findings = parser.parse(args.input)

    if args.verbose:
        print(f"[+] Parsed {len(findings)} raw findings")

    findings = deduplicate(findings)
    if args.verbose:
        print(f"[+] {len(findings)} findings after deduplication")

    findings = assign_cvss(findings)

    if args.llm:
        if args.verbose:
            print(f"[+] Running LLM false-positive filter ({len(findings)} findings)...")
        findings = filter_false_positives(findings, verbose=args.verbose)
        fp_count = sum(1 for f in findings if f.false_positive)
        if args.verbose:
            print(f"[+] {fp_count} false positives identified")
        findings = [f for f in findings if not f.false_positive]

    if args.format in ("json", "both"):
        out = f"{args.output}.json"
        write_json(findings, out)
        if args.verbose:
            print(f"[+] JSON report written to {out}")

    if args.format in ("markdown", "both"):
        out = f"{args.output}.md"
        write_markdown(findings, out)
        if args.verbose:
            print(f"[+] Markdown report written to {out}")

    # Always print summary to stdout
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    print(f"\nTotal: {len(findings)} findings")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_sev:
            print(f"  {sev.upper():10s} {by_sev[sev]}")


if __name__ == "__main__":
    main()
