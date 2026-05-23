# P1 SAST+DAST Triage Tool — Design Writeup

## Problem

Running SAST and DAST scanners on a real codebase produces hundreds of findings. Most are duplicates or false positives. A junior analyst wastes hours manually reviewing noise before reaching the one SQLi that actually matters. This tool automates that triage step.

## Architecture Decisions

### Unified Finding Schema
Every scanner has a different output format (Semgrep JSON, Bandit JSON, ZAP XML). Rather than treating them as separate outputs, all findings normalize to a single `Finding` dataclass with a stable hash ID derived from `rule_id + file_path + line_number`. This makes deduplication and reporting scanner-agnostic.

### Hash-Based Deduplication
Two findings are duplicates if they point to the same root cause: same rule, same file, same line. When duplicates exist across scanners, the higher-severity version is kept. This handles the common case where Semgrep and Bandit both flag the same SQL injection — you get one finding, not two.

### Conservative CVSS Defaults
Real CVSS scoring requires 8 attack vector metrics that static analysis can't determine without runtime context. Instead, severity bands map to baseline scores (critical=9.5, high=7.5, medium=5.5, low=2.5) with CWE-specific bumps for highly exploitable categories (SQLi, command injection, hardcoded credentials). This gives useful signal without pretending to be precise.

### LLM as FP Filter, Not Oracle
The LLM layer (claw-core Ollama) doesn't replace human review — it filters obvious false positives. The model receives the full finding context (scanner, rule, severity, code snippet, CWE) and classifies TP vs FP with a reason. Findings the model can't classify (API error, malformed response) stay in the report as "unreviewed" rather than being silently dropped. This is the right failure mode: show everything, flag uncertainty.

### Model Selection
`llama3.2:3b` is the default rather than `llama3.1:70b`. The FP classification task is simple enough that a 3B model handles it correctly (tested: SQLi and hardcoded secret both classified TP). The 70B model adds latency without meaningfully better results for binary classification with clear evidence in the prompt. Override is available via `TRIAGE_MODEL` env var.

### Zero Dependencies
Pure Python 3.11+ stdlib. No pip install, no virtualenv required. This matters for running in CI/CD pipelines or restricted environments where installing packages is friction.

## What's Missing (MVP Scope)

- **Multi-file ingestion**: currently one file per run. A future `--dir` flag could batch all scanner outputs in a directory.
- **Remediation suggestions**: the LLM prompt could be extended to generate fix suggestions per finding, not just TP/FP.
- **CI/CD integration**: a `--fail-on-severity high` flag would let this gate a pipeline.
- **Web UI**: the Markdown report is good for ad-hoc review; a Flask dashboard would be better for team use.

## Relevance to Security Work

SAST/DAST triage is a daily task for AppSec analysts and developers. Tools like Semgrep and Bandit are noisy by design — they prefer false positives over false negatives. The value add is the filtering layer: an analyst who can run this tool, review the filtered output, and focus human judgment on real findings is faster and more effective than one manually reviewing raw scanner output.
