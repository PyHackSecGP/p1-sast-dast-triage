"""SAST+DAST Triage Tool — CLI entry point."""

from __future__ import annotations

import argparse
import logging
import sys
from importlib.metadata import PackageNotFoundError, version

from core import apply_suppressions, assign_risk_score, deduplicate, filter_false_positives
from output import write_html, write_json, write_markdown, write_sarif
from parsers import PARSERS

log = logging.getLogger("triage")


def _tool_version() -> str:
    try:
        return version("sast-dast-triage")
    except PackageNotFoundError:
        return "0.0.0+source"


def _configure_logging(verbosity: int, quiet: bool) -> None:
    """Set root logger level from -v/-vv/--quiet.

    - ``--quiet``: WARNING and above only (silences per-finding progress).
    - default: INFO (stage-level progress).
    - ``-v``: DEBUG on the triage logger.
    - ``-vv``: DEBUG on every logger (parser warnings, LLM internals).
    """
    if quiet:
        level = logging.WARNING
    elif verbosity >= 1:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    if verbosity < 2:
        # Silence third-party/library debug spam unless -vv.
        for noisy in ("urllib3", "urllib"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Triage SAST/DAST scanner output: deduplicate, score, filter false positives.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {_tool_version()}")
    p.add_argument("--input", "-i", required=True, help="Path to scanner output file")
    p.add_argument(
        "--scanner",
        "-s",
        required=True,
        choices=list(PARSERS),
        help="Scanner that produced the output",
    )
    p.add_argument(
        "--output",
        "-o",
        default="report",
        help="Output file path without extension (default: report)",
    )
    p.add_argument(
        "--format",
        "-f",
        choices=["json", "markdown", "sarif", "html", "both", "all"],
        default="both",
        help="Output format: both=json+markdown, all=json+markdown+sarif+html (default: both)",
    )
    p.add_argument(
        "--suppress",
        metavar="FILE",
        default="suppressions.yaml",
        help="Path to suppressions.yaml (default: suppressions.yaml in CWD; skipped if absent)",
    )
    p.add_argument(
        "--llm",
        action="store_true",
        help="Run LLM false-positive filter (uses local Ollama; slower)",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="-v: DEBUG on triage logger; -vv: DEBUG everywhere",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-stage progress (WARNING and above only)",
    )
    return p.parse_args()


def main() -> None:
    """Run the triage pipeline."""
    args = parse_args()
    _configure_logging(args.verbose, args.quiet)

    log.info("Parsing %s output from %s", args.scanner, args.input)
    parser = PARSERS[args.scanner]()
    findings = parser.parse(args.input)
    log.info("Parsed %d raw findings", len(findings))

    findings = deduplicate(findings)
    log.info("%d findings after deduplication", len(findings))

    findings = assign_risk_score(findings)

    findings = apply_suppressions(findings, args.suppress)
    suppressed_count = sum(1 for f in findings if f.status == "suppressed")
    if suppressed_count:
        log.info("%d finding(s) suppressed by %s", suppressed_count, args.suppress)

    if args.llm:
        log.info("Running LLM false-positive filter on %d findings", len(findings))
        findings = filter_false_positives(findings, verbose=args.verbose > 0)
        fp_count = sum(1 for f in findings if f.status == "likely_fp")
        unreviewed = sum(1 for f in findings if f.status == "unreviewed")
        log.info(
            "LLM: %d likely FP, %d unreviewed (LLM error), %d confirmed (kept in report)",
            fp_count,
            unreviewed,
            len(findings) - fp_count - unreviewed,
        )

    fmt = args.format
    if fmt in ("json", "both", "all"):
        out = f"{args.output}.json"
        write_json(findings, out)
        log.info("JSON report written to %s", out)

    if fmt in ("markdown", "both", "all"):
        out = f"{args.output}.md"
        write_markdown(findings, out)
        log.info("Markdown report written to %s", out)

    if fmt in ("sarif", "all"):
        out = f"{args.output}.sarif"
        write_sarif(findings, out)
        log.info("SARIF report written to %s", out)

    if fmt in ("html", "all"):
        out = f"{args.output}.html"
        write_html(findings, out)
        log.info("HTML report written to %s", out)

    # Severity histogram is product output, not diagnostic logging — stdout.
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    print(f"\nTotal: {len(findings)} findings")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in by_sev:
            print(f"  {sev.upper():10s} {by_sev[sev]}")


if __name__ == "__main__":
    main()
