# P1 — SAST+DAST Triage Tool

Aggregates scanner output from Semgrep, Bandit, and OWASP ZAP into a single deduplicated, scored, and LLM-triaged finding list. Cuts through false positives so you focus on real issues.

## Features

- **Multi-scanner ingestion** — Semgrep JSON, Bandit JSON, OWASP ZAP XML
- **Deduplication** — identical findings across scanners collapsed by rule+file+line hash
- **CVSS scoring** — automated base scores with CWE-based severity nudges
- **LLM false-positive filter** — each finding sent to local Ollama (claw-core) for TP/FP classification
- **Dual output** — JSON (machine-readable) and Markdown (human-readable report)
- **Zero pip dependencies** — pure Python 3.11+ stdlib

## Usage

```bash
# Basic triage (no LLM)
python3 main.py --input results.json --scanner semgrep --output report

# With LLM false-positive filter
python3 main.py --input results.json --scanner semgrep --llm --verbose

# Bandit
python3 main.py -i bandit_output.json -s bandit -o triage_report -f markdown

# OWASP ZAP
python3 main.py -i zap_report.xml -s zap -o triage_report --llm
```

### Flags

| Flag | Description |
|---|---|
| `--input / -i` | Path to scanner output file (required) |
| `--scanner / -s` | `semgrep` \| `bandit` \| `zap` (required) |
| `--output / -o` | Output path without extension (default: `report`) |
| `--format / -f` | `json` \| `markdown` \| `both` (default: `both`) |
| `--llm` | Enable LLM false-positive filter via claw-core |
| `--verbose / -v` | Show per-finding progress |

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TRIAGE_MODEL` | `llama3.2:3b` | Ollama model for FP classification |

## Generating Scanner Output

```bash
# Semgrep
semgrep --json --output semgrep_results.json .

# Bandit
bandit -r . -f json -o bandit_results.json

# OWASP ZAP
zap.sh -cmd -quickurl http://localhost:5000 -quickout zap_results.xml
```

## Architecture

```
parsers/      semgrep.py, bandit.py, zap.py  →  normalized Finding objects
core/         dedup.py, scorer.py, llm.py    →  pipeline stages
output/       json_report.py, markdown_report.py
main.py       CLI entry point
```

### Finding Schema

Every scanner output normalizes to the same `Finding` dataclass:

```
id            sha256 hash of rule_id + file_path + line_number
scanner       semgrep | bandit | zap
rule_id       scanner-specific rule identifier
severity      critical | high | medium | low | info
cvss_score    float 0.0–10.0
file_path     affected file or URL
line_number   line number (0 for web findings)
message       human-readable description
code_snippet  relevant source code
cwe           CWE identifier
false_positive  True | False | None (unreviewed)
fp_reason     LLM explanation
```

## LLM Integration

Uses the local Ollama instance at `http://100.126.22.55:11434`. Each finding is sent with full context (scanner, rule, severity, code snippet, CWE) and the model returns a verdict + one-sentence reason. Findings classified as false positives are excluded from the final report.

Default model: `llama3.2:3b` (stays resident, fast inference). Override with `TRIAGE_MODEL=llama3.1:70b` for higher accuracy.

## Tests

```bash
python3 tests/test_parsers.py
python3 tests/test_dedup.py
```
