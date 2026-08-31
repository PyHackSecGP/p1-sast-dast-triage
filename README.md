# P1 — SAST+DAST Triage Tool

Security scanners are noisy. Run Semgrep + Bandit + ZAP on any real codebase and you get 200+ findings — 80% duplicates or false positives. No developer fixes 200 findings; they close the ticket.

P1 collapses that noise into a ranked, deduplicated, human-reviewable list with LLM-assisted triage and SARIF output for GitHub code scanning integration.

---

## How It Works

```
Raw scanner output
      ↓
  1. Parse       — normalize Semgrep / Bandit / ZAP / Trivy / Nuclei into one schema
      ↓
  2. Deduplicate — collapse cross-scanner duplicates by CWE + file + line
      ↓
  3. Score       — CWE heuristic baseline + multi-scanner agreement bump
      ↓
  4. Suppress    — suppressions.yaml skips test files, vendored code, accepted risks
      ↓
  5. LLM Filter  — local Ollama reviews each finding → verdict + confidence score
      ↓
  Reports: JSON / Markdown / SARIF / HTML
```

### Stage 2 — Cross-Scanner Deduplication

The core insight: Semgrep calls SQL injection `python.lang.security.sqli.raw-query-format-string`. Bandit calls it `B608`. Naively hashing by rule ID makes them look like two different findings at the same line.

Fix: hash on `CWE + file_path + line_number`. Both scanners emit `CWE-89` — same hash, they merge. The merged finding carries `sources: ["semgrep:...", "bandit:B608"]`.

```python
# parsers/base.py
if self.cwe:
    key = f"{self.cwe}:{self.file_path}:{self.line_number}"
```

**Why it matters:** like three doctors independently flagging the same shadow on an X-ray. Multi-scanner agreement is the strongest true-positive signal available.

### Stage 3 — Risk Scoring

Not CVSS. A **CWE-based heuristic risk score** (0–10) — honest about what static analysis can and can't know.

| Component | Logic |
|---|---|
| Severity baseline | `critical=9.5`, `high=7.5`, `medium=5.5`, `low=2.5` |
| CWE exploitability bump | SQLi `CWE-89` → `+1.0`, XSS `CWE-79` → `+0.5`, hardcoded creds `CWE-798` → `+1.0` |
| Agreement bump | `+0.5` per extra scanner that also flagged the same finding |

SQLi flagged by both Semgrep and Bandit at high severity: `7.5 + 1.0 + 0.5 = 9.0/10`.

CVSS requires knowing attack vector, authentication scope, and impact — none of which static analysis can determine without runtime context. A heuristic that's honest about its limits beats a fake CVSS score.

### Stage 4 — Suppression File

`suppressions.yaml` — skip known-good findings before LLM triage:

```yaml
- file_glob: "tests/*"
  reason: "Test fixtures, not production code"

- rule_id: B105
  file_glob: "config/*"
  reason: "Hardcoded token in config template — not a real secret"

- rule_id: python.lang.security.audit.sqli.raw-query-format-string
  reason: "Accepted risk — parameterized query confirmed at call site"
```

Rules: `rule_id` alone, `file_glob` alone, or both together (AND logic). Suppressed findings are **not deleted** — they appear in a dedicated report section so the decision is auditable.

### Stage 5 — LLM False-Positive Filter

Local Ollama (`llama3.2:3b` default). No data leaves the machine — critical for real source code.

LLM receives: scanner, rule, severity, file, line, code snippet, CWE. Returns:

```json
{
  "verdict": "false_positive",
  "confidence": 0.91,
  "reason": "user_id validated at line 30 before reaching this query"
}
```

Three design decisions:

1. **LLM never deletes findings.** Sets `status: "likely_fp"`. Human decides. A 3B local model is not trustworthy enough to silently remove real vulns.
2. **Confidence score (0–1).** Binary TP/FP from a small model is overconfident. A `0.65` FP warrants review; `0.95` does not.
3. **Graceful fallback.** Ollama down, model error, no JSON — finding gets `status: "unreviewed"`, not `"confirmed"`. Failing safe keeps the finding visible.

### SARIF Output → GitHub PR Annotations

SARIF is the format GitHub code scanning reads natively. Upload via CI and findings appear as **inline PR annotations** — exactly where the developer sees them during review:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
    category: semgrep-triage
```

That's the difference between a security report nobody reads and a comment on line 42 of the PR they're reviewing right now.

---

## Usage

```bash
# Basic triage (no LLM)
python3 main.py -i results.json -s semgrep -o report

# With LLM filter
python3 main.py -i results.json -s semgrep -o report --llm

# With suppression file
python3 main.py -i results.json -s bandit --suppress suppressions.yaml --llm

# All 4 formats at once (json + markdown + sarif + html)
python3 main.py -i zap_report.xml -s zap -f all --llm

# Bandit
python3 main.py -i bandit_output.json -s bandit -o triage_report -f markdown

# OWASP ZAP
python3 main.py -i zap_report.xml -s zap -o triage_report --llm
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--input / -i` | required | Path to scanner output file |
| `--scanner / -s` | required | `semgrep` \| `bandit` \| `zap` \| `trivy` \| `nuclei` |
| `--output / -o` | `report` | Output path without extension |
| `--format / -f` | `both` | `json` \| `markdown` \| `sarif` \| `html` \| `both` \| `all` |
| `--suppress` | `suppressions.yaml` | Path to suppression file (silently skipped if absent) |
| `--llm` | off | Enable LLM false-positive filter |
| `-v / -vv` | INFO | `-v` debug on triage logger; `-vv` debug everywhere |
| `--quiet` | off | WARNING and above only |

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama endpoint |
| `TRIAGE_MODEL` | `llama3.2:3b` | Model for FP classification |

## Generating Scanner Output

```bash
# Semgrep
semgrep scan --json --output semgrep_results.json .

# Bandit
bandit -r . -f json -o bandit_results.json --exit-zero

# OWASP ZAP
zap.sh -cmd -quickurl http://localhost:5000 -quickout zap_results.xml

# Trivy (container images)
trivy image --format json --output trivy_results.json myapp:latest

# Nuclei
nuclei -u https://target.com -json -o nuclei_results.jsonl
```

---

## Architecture

```
parsers/
  base.py          Finding dataclass + normalize_cwe() + BaseParser
  semgrep.py       Semgrep JSON → Finding list
  bandit.py        Bandit JSON → Finding list
  zap.py           OWASP ZAP XML → Finding list
  trivy.py         Trivy JSON → Finding list
  nuclei.py        Nuclei JSONL → Finding list

core/
  dedup.py         Cross-scanner merge by CWE+file+line; tracks sources[]
  scorer.py        CWE heuristic risk score + agreement bump
  llm.py           Ollama FP filter; verdict + confidence; never deletes
  suppression.py   suppressions.yaml loader; rule_id + file_glob matching

output/
  json_report.py   Machine-readable JSON
  markdown_report.py  Human-readable Markdown with FP + suppressed sections
  sarif_report.py  SARIF 2.1.0 for GitHub code scanning upload
  html_report.py   Self-contained dark-theme HTML; no external deps

main.py            CLI entry point
```

### Finding Schema

```
scanner       semgrep | bandit | zap | trivy | nuclei
rule_id       scanner-specific rule identifier
severity      critical | high | medium | low | info
risk_score    float 0.0–10.0 (CWE heuristic, NOT a computed CVSS vector)
file_path     affected file or URL
line_number   source line (0 for web findings)
cwe           normalized CWE-NNN identifier
sources       ["semgrep:rule", "bandit:B608"] — multi-scanner agreement trail
status        confirmed | likely_fp | unreviewed | suppressed
false_positive  True | False | None (unreviewed)
confidence    float 0.0–1.0 | None (LLM confidence in verdict)
fp_reason     LLM explanation or suppression reason
```

---

## Tests

```bash
python -m pytest tests/ -v          # 90 tests
python -m pytest tests/ -q          # summary only
```

CI runs on Python 3.11 and 3.12 with coverage ≥ 85% and an OPSEC guard that blocks internal IPs/hostnames from reaching tracked files.

---

## Why Not Just Use GitHub Advanced Security?

GHAS costs $49/user/month and requires GitHub Enterprise. P1 works on any git host, any scanner, any language, zero cloud dependency, and the LLM filter runs fully local — no source code leaves the machine.
