# P1 — SAST+DAST Triage Tool

Aggregates output from multiple SAST and DAST scanners, deduplicates findings across tool boundaries using CWE normalization, scores by exploitability and cross-scanner agreement, filters false positives via a local LLM, and outputs SARIF for GitHub code scanning integration.

---

## Pipeline

```
Raw scanner output
      ↓
  1. Parse       — normalize Semgrep / Bandit / ZAP / Trivy / Nuclei into one schema
      ↓
  2. Deduplicate — collapse cross-scanner duplicates by CWE + file + line
      ↓
  3. Score       — CWE heuristic baseline + multi-scanner agreement bump
      ↓
  4. Suppress    — suppressions.yaml skips known-good paths and accepted risks
      ↓
  5. LLM Filter  — local Ollama classifies each finding with verdict + confidence score
      ↓
  Reports: JSON / Markdown / SARIF / HTML
```

---

## Features

- **Cross-scanner deduplication** — findings merged by `CWE + file_path + line_number`, not rule ID. Semgrep `python.lang.security.sqli.*` and Bandit `B608` for the same SQLi at the same line collapse to one finding. Multi-scanner agreement is tracked in `sources[]` and lifts the risk score.
- **CWE-based risk scoring** — severity baseline + exploitability bump per CWE + `+0.5` per additional scanner that agreed. Honest heuristic; not a computed CVSS vector.
- **Suppression file** — `suppressions.yaml` with `rule_id`, `file_glob`, or both (AND logic). Suppressed findings stay in the report with a reason — no silent drops.
- **LLM false-positive filter** — local Ollama endpoint, zero data exfiltration. Returns `verdict + confidence (0–1) + reason`. Never deletes findings; sets `status: "likely_fp"` so the human decides. Graceful fallback to `status: "unreviewed"` on model error.
- **SARIF output** — uploads to GitHub Security tab via `github/codeql-action/upload-sarif`; findings appear as inline PR annotations.
- **HTML report** — self-contained dark-theme single file, no external dependencies.
- **5 parsers** — Semgrep JSON, Bandit JSON, OWASP ZAP XML, Trivy JSON, Nuclei JSONL.

---

## Usage

```bash
# Basic triage
python3 main.py -i results.json -s semgrep -o report

# With LLM false-positive filter
python3 main.py -i results.json -s semgrep -o report --llm

# With suppression file
python3 main.py -i results.json -s bandit --suppress suppressions.yaml --llm

# All 4 output formats at once
python3 main.py -i zap_report.xml -s zap -f all --llm
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--input / -i` | required | Path to scanner output file |
| `--scanner / -s` | required | `semgrep` \| `bandit` \| `zap` \| `trivy` \| `nuclei` |
| `--output / -o` | `report` | Output path without extension |
| `--format / -f` | `both` | `json` \| `markdown` \| `sarif` \| `html` \| `both` \| `all` |
| `--suppress` | `suppressions.yaml` | Suppression file path (silently skipped if absent) |
| `--llm` | off | Enable LLM false-positive filter |
| `-v / -vv` | INFO | Debug logging (`-vv` for all loggers) |
| `--quiet` | off | WARNING and above only |

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama endpoint URL |
| `TRIAGE_MODEL` | `llama3.2:3b` | Model used for FP classification |

---

## Suppression File

```yaml
# suppressions.yaml
- file_glob: "tests/*"
  reason: "Test fixtures, not production code"

- rule_id: B105
  file_glob: "config/*"
  reason: "Hardcoded token in config template — not a real secret"

- rule_id: python.lang.security.audit.sqli.raw-query-format-string
  reason: "Accepted risk — parameterised at call site, reviewed 2026-08-30"
```

Matching logic: `rule_id` alone, `file_glob` alone, or both fields together (AND). Suppressed findings get `status: "suppressed"` and appear in a dedicated report section for audit visibility.

---

## SARIF → GitHub Code Scanning

```yaml
# .github/workflows/sast.yml
- name: Triage Semgrep output
  run: python3 main.py -i semgrep_results.json -s semgrep -o report_semgrep -f sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report_semgrep.sarif
    category: semgrep-triage
```

See [`.github/workflows/sast.yml`](.github/workflows/sast.yml) for the full CI workflow.

---

## Generating Scanner Output

```bash
# Semgrep
semgrep scan --json --output semgrep_results.json .

# Bandit
bandit -r . -f json -o bandit_results.json --exit-zero

# OWASP ZAP
zap.sh -cmd -quickurl http://target -quickout zap_results.xml

# Trivy
trivy image --format json --output trivy_results.json myapp:latest

# Nuclei
nuclei -u https://target.com -json -o nuclei_results.jsonl
```

---

## Architecture

```
parsers/
  base.py            Finding dataclass, normalize_cwe(), BaseParser ABC
  semgrep.py         Semgrep JSON → Finding list
  bandit.py          Bandit JSON → Finding list
  zap.py             OWASP ZAP XML → Finding list
  trivy.py           Trivy JSON → Finding list
  nuclei.py          Nuclei JSONL → Finding list

core/
  dedup.py           Cross-scanner merge; preserves sources[] agreement trail
  scorer.py          CWE heuristic risk score + agreement bump
  llm.py             Ollama FP filter; confidence score; status-based (no deletes)
  suppression.py     YAML loader; rule_id + file_glob matching

output/
  json_report.py     Machine-readable JSON
  markdown_report.py Markdown with active / likely-FP / suppressed sections
  sarif_report.py    SARIF 2.1.0 with CWE relationships and suppression entries
  html_report.py     Self-contained HTML, no external deps

main.py              CLI entry point
```

### Finding Schema

| Field | Type | Description |
|---|---|---|
| `scanner` | `str` | Source scanner name |
| `rule_id` | `str` | Scanner-specific rule identifier |
| `severity` | `str` | `critical \| high \| medium \| low \| info` |
| `risk_score` | `float` | 0–10 CWE heuristic (not a computed CVSS vector) |
| `file_path` | `str` | Affected file or URL |
| `line_number` | `int` | Source line (0 for web findings) |
| `cwe` | `str` | Normalised `CWE-NNN` identifier |
| `sources` | `list[str]` | `["semgrep:rule", "bandit:B608"]` — agreement trail |
| `status` | `str` | `confirmed \| likely_fp \| unreviewed \| suppressed` |
| `confidence` | `float \| None` | LLM confidence in verdict (0–1); `None` = unreviewed |
| `fp_reason` | `str` | LLM explanation or suppression reason |

---

## Tests

```bash
python -m pytest tests/ -v          # 90 tests
python -m pytest tests/ --cov=core --cov=parsers --cov-branch
```

CI runs on Python 3.11 and 3.12 with coverage ≥ 85% enforced. An OPSEC check blocks internal IPs and hostnames from reaching tracked files.
