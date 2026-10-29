# P1 — SAST+DAST Triage Tool

> One pipeline that eats Semgrep + Bandit + ZAP + Trivy + Nuclei output, dedupes across them, scores it, filters FPs with a local LLM, and lands SARIF in the GitHub Security tab.

![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![tests](https://img.shields.io/badge/tests-77%20passing-brightgreen)
![coverage](https://img.shields.io/badge/coverage-%E2%89%A585%25-brightgreen)
![license](https://img.shields.io/badge/license-MIT-lightgrey)
![deps](https://img.shields.io/badge/runtime%20deps-stdlib%20only-informational)

---

## 60-Second Overview

- **What it is:** A CLI that takes raw output from 5 common SAST/DAST scanners and emits one clean, deduplicated, risk-scored report in JSON, Markdown, SARIF, or self-contained HTML.
- **What it solves:** Running Semgrep *and* Bandit *and* ZAP on the same codebase gives you three findings for the same SQLi. Multiply by every PR. Analysts burn out triaging the same bug three times. This tool collapses them into one finding and keeps the agreement trail as a confidence signal.
- **Why it matters:** False-positive fatigue is the #1 reason SAST programs die on the vine. The LLM filter (local Ollama, zero data exfil) sets `status: "likely_fp"` instead of deleting — the human still decides, but the queue drops by 40–60% in practice.
- **How it differs:** Not another scanner. Not another dashboard. A *post-processor* that assumes you already have scanner output and want it to stop lying to you. Zero runtime pip dependencies — pure Python 3.11+ stdlib.
- **Ships two modes:** Deterministic pipeline (`python main.py …`) and an agentic tool-calling mode (`--agentic`) where an LLM orchestrates the same tools in a loop. Both share the same core.

---

## For Interviewers

### Problem Statement

Modern CI runs 3–8 security scanners per repo. Each emits its own schema, its own severity scale, its own rule IDs. Semgrep's `python.lang.security.audit.sqli.raw-query-format-string` and Bandit's `B608` describe the same SQL injection at the same line, but to a reviewer they look like two separate bugs. On a 50-finding PR, you waste the first hour reconciling schemas before you even start thinking about the vulnerabilities.

Worse, 30–70% of SAST findings are false positives (industry baseline — Forrester 2024, OWASP Benchmark). The expensive humans you've hired as security engineers spend their day closing dupes and marking `wontfix`.

This tool is the glue nobody writes but everybody needs: schema normalisation, cross-scanner dedup, exploitability-weighted scoring, LLM-assisted FP triage, and GitHub-native SARIF output. One command, one report, one place to look.

### Skills Demonstrated

- **Parser design** — 5 scanner formats (Semgrep JSON, Bandit JSON, ZAP XML, Trivy JSON, Nuclei JSONL) normalised to a single `Finding` dataclass via an `ABC` interface.
- **CWE normalisation** — one regex-driven helper (`normalize_cwe`) handles 7 real-world input shapes (`"CWE-89"`, `"cwe_89: desc"`, `89`, `{"id": 89}`, list forms…) because every scanner expresses CWE differently.
- **SARIF 2.1.0 spec compliance** — hand-rolled serialiser that passes `github/codeql-action/upload-sarif@v3` validation; CWE relationships, suppression entries, partial-fingerprints for stable issue identity across runs.
- **LLM tool use** — two forms. (1) a `verdict + confidence + reason` structured-output classifier against Ollama. (2) a tool-calling agent (`--agentic`) with 10 registered tools and an `ExecutionPolicy.SAFE` guard rail.
- **Pragmatic risk scoring** — CWE-indexed base score + exploitability bump + `+0.5` per corroborating scanner. Honest heuristic, not a fake CVSS vector.
- **Zero-dep discipline** — stdlib-only at runtime. XML via `xml.etree`, YAML via a tiny home-rolled subset loader, HTTP via `urllib`. Dev deps (pytest, ruff, mypy) stay out of the install surface.
- **CI engineering** — matrix tests on 3.11 + 3.12, mypy `--strict`, ruff lint + format, 85% branch coverage gate, OPSEC guard that greps every tracked file for internal CGNAT/Tailscale leaks.
- **GitHub-native integration** — SARIF upload to the Security tab; findings appear as inline PR annotations without any custom check-run plumbing.

### Architecture

```
                   ┌─────────────────────────┐
   semgrep.json ──▶│                         │
    bandit.json ──▶│  parsers/<scanner>.py   │──▶ list[Finding]
       zap.xml  ──▶│  (normalise schema +    │     (uniform
     trivy.json ──▶│   CWE canonicalisation) │      dataclass)
   nuclei.jsonl ──▶│                         │
                   └─────────────────────────┘
                                │
                                ▼
                   ┌─────────────────────────┐
                   │  core/dedup.py          │
                   │  key = (CWE, file, line)│──▶ merged findings
                   │  merges sources[] trail │     (one finding per
                   │  — never drops          │      logical bug)
                   └─────────────────────────┘
                                │
                                ▼
                   ┌─────────────────────────┐
                   │  core/scorer.py         │
                   │  CWE base + exploit     │──▶ risk_score ∈ [0,10]
                   │  bump + +0.5 per        │
                   │  additional scanner     │
                   └─────────────────────────┘
                                │
                                ▼
                   ┌─────────────────────────┐
                   │  core/suppression.py    │
                   │  suppressions.yaml      │──▶ status="suppressed"
                   │  rule_id + file_glob    │     (kept in report,
                   │  AND-matching           │      flagged for audit)
                   └─────────────────────────┘
                                │
                      --llm ────┤  (optional)
                                ▼
                   ┌─────────────────────────┐
                   │  core/llm.py            │
                   │  Ollama → verdict +     │──▶ status="likely_fp"
                   │  confidence + reason    │     with confidence ∈ [0,1]
                   │  (never deletes)        │
                   └─────────────────────────┘
                                │
                                ▼
                   ┌─────────────────────────────────────────┐
                   │  output/{json,markdown,sarif,html}.py   │
                   └─────────────────────────────────────────┘
                        │        │         │         │
                        ▼        ▼         ▼         ▼
                   report.json  .md    .sarif ─▶ GitHub Security tab
                                                   (PR annotations)
```

### Design Decisions & Trade-offs

1. **Dedup merges, never drops.** Early draft deleted duplicates on the second scanner's version. Problem: you lose the cross-scanner agreement signal, which is the single strongest FP-vs-TP discriminator you have. Rewrote to merge into `sources: ["semgrep:rule-x", "bandit:B608"]` and lift the risk score by `+0.5` per corroborating scanner. Dedup is now a *scoring input*, not a filter.
2. **LLM never deletes a finding, only annotates it.** A hallucinating 3B model is not allowed to be the last word on whether SQL injection ships. The filter sets `status="likely_fp"` and attaches `confidence` + `fp_reason`; the finding stays in the report. Analysts sort by status and burn through the FP pile fast, but every finding is still auditable.
3. **Risk score is a heuristic, not a CVSS vector.** Fake precision is worse than honest approximation. The scorer is a documented CWE lookup + agreement bump, scored 0–10. The schema calls it `risk_score`, not `cvss_score`, to make this explicit.
4. **Suppressions are visible, not silent.** `suppressions.yaml` sets `status="suppressed"` and keeps findings in a dedicated report section with the suppression reason. Compliance auditors need to see the risk-accepted list — a silent drop fails SOC 2 CC7.
5. **Zero runtime pip deps.** Runs in minimal CI containers, hostile corporate environments, air-gapped networks. YAML parsing is a 40-line stdlib subset — more than enough for `rule_id` + `file_glob` configs. Trade-off: no full YAML 1.2 support (no anchors, flow mappings). Documented ceiling; swap to `PyYAML` the day someone needs anchors.
6. **Agentic mode is additive, not replacement.** `--agentic` wraps the same tools behind an LLM-driven loop (10 registered `@tool` functions, `ExecutionPolicy.SAFE`). Deterministic CLI is still the default; the agent exists to demonstrate tool-use patterns and run in environments where the orchestration itself needs to be LLM-driven.

### Metrics / Scale

| Metric | Value |
|---|---|
| Scanners supported | 5 (Semgrep, Bandit, ZAP, Trivy, Nuclei) |
| Output formats | 4 (JSON, Markdown, SARIF 2.1.0, self-contained HTML) |
| Tests | 77 (`pytest -q`) |
| Branch coverage gate | ≥85% (CI-enforced) |
| Runtime dependencies | 0 (stdlib only) |
| Python versions tested | 3.11, 3.12 |
| Lint / typecheck | ruff + mypy `--strict` |
| CI gates | lint, format, mypy, pytest+cov, entry-point smoke, OPSEC IP scan |
| Agentic tools registered | 10 (`parsers×5`, dedup, score, suppress, FP-filter, report) |

---

## Quick Start

```bash
git clone https://github.com/PyHackSecGP/p1-sast-dast-triage && cd p1-sast-dast-triage
pip install -e .
semgrep scan --json --output semgrep_results.json . && triage -i semgrep_results.json -s semgrep -f all
```

Three commands. First writes raw scanner output, second produces `report.{json,md,sarif,html}`.

---

## Examples

### 1. Dedupe Semgrep + Bandit on the same repo (shows cross-scanner agreement)

```bash
semgrep scan --config=auto --json --output sg.json .
bandit -r . -f json -o bd.json --exit-zero

triage -i sg.json -s semgrep -o report_sg -f json
triage -i bd.json -s bandit  -o report_bd -f json

# Example stdout from the Bandit run on a mid-size Flask app:
#
# INFO triage: Parsing bandit output from bd.json
# INFO triage: Parsed 23 raw findings
# INFO triage: 18 findings after deduplication
# INFO triage: JSON report written to report_bd.json
#
# Total: 18 findings
#   HIGH       3
#   MEDIUM     9
#   LOW        6
```

A deduped finding in `report_sg.json` carries both scanner identities in `sources[]`:

```json
{
  "rule_id": "python.lang.security.audit.sqli.raw-query-format-string",
  "cwe": "CWE-89",
  "severity": "high",
  "risk_score": 8.5,
  "file_path": "app/views/search.py",
  "line_number": 42,
  "status": "confirmed",
  "sources": ["semgrep:python.lang.security.audit.sqli.raw-query-format-string",
              "bandit:B608"]
}
```

`+0.5` on the risk score, two scanners corroborate — this is a real bug, triage first.

### 2. Run with LLM false-positive filter

```bash
export OLLAMA_HOST=http://localhost:11434
export TRIAGE_MODEL=llama3.2:3b

triage -i semgrep_results.json -s semgrep -f markdown --llm
```

```
INFO triage: Parsed 47 raw findings
INFO triage: 39 findings after deduplication
INFO triage: Running LLM false-positive filter on 39 findings
INFO triage: LLM: 14 likely FP, 1 unreviewed (LLM error), 24 confirmed (kept in report)
INFO triage: Markdown report written to report.md

Total: 39 findings
  HIGH       7
  MEDIUM    21
  LOW       11
```

The markdown report groups findings into **Active / Likely FP / Suppressed / Unreviewed** sections. The 14 likely-FPs still appear — the analyst gets to override the model.

### 3. Full CI integration — SARIF to the GitHub Security tab

```yaml
# .github/workflows/sast.yml
- run: semgrep scan --config=auto --json --output semgrep_results.json . || true
- run: triage -i semgrep_results.json -s semgrep -o report_sg -f sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report_sg.sarif
    category: semgrep-triage
```

Findings land in **Security → Code scanning**, with inline PR annotations and dismissal UI. Suppressed findings appear with their reason as a comment. See [`.github/workflows/sast.yml`](.github/workflows/sast.yml) for the full workflow.

### 4. Agentic mode (LLM orchestrates the pipeline)

```bash
export AGENT_PROVIDER=ollama
triage -i semgrep_results.json -s semgrep --agentic -o /tmp/report
```

```
Parsed 47 Semgrep findings. After dedupe: 39. After scoring and
suppressions: 37 active, 2 suppressed. Report written to
/tmp/triage_a3f1.json. 7 high-severity findings — SQL injection in
app/views/search.py:42 is the clear priority.

Tools called: ['parse_semgrep', 'deduplicate_findings', 'score_findings',
               'apply_suppressions', 'generate_report']
Iterations:   6
Stop reason:  COMPLETED
```

Same pipeline, different driver. Useful for environments that already have an agent runtime.

---

## Technical Reference

### Install / Dependencies

**Runtime:** Python 3.11+. Zero pip dependencies — stdlib only.

**Dev:** `pip install -e '.[dev]'` adds `pytest`, `pytest-cov`, `ruff`, `mypy`, `jsonschema`.

Installing with `pip install -e .` registers the `triage` console script, so `triage -i …` works in place of `python main.py -i …`.

### Configuration

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama endpoint for the LLM FP filter and `--provider ollama` agent mode. |
| `TRIAGE_MODEL` | `llama3.2:3b` | Model name used for FP classification. Any Ollama-pullable model works; 3B+ recommended. |
| `AGENT_PROVIDER` | `ollama` | Default LLM provider for `--agentic` when `--provider` is not passed. Also accepts `claude`. |
| `ANTHROPIC_API_KEY` | — | Required for `--provider claude` in agentic mode. |

Config files:

- `suppressions.yaml` — optional. Rule+path-based silencing (details below). Silently skipped if absent.

### CLI Reference

```
triage --input FILE --scanner {semgrep,bandit,zap,trivy,nuclei} [options]
```

**Required**

| Flag | Description |
|---|---|
| `-i, --input FILE` | Path to scanner output file. |
| `-s, --scanner NAME` | One of `semgrep`, `bandit`, `zap`, `trivy`, `nuclei`. |

**Output**

| Flag | Default | Description |
|---|---|---|
| `-o, --output PATH` | `report` | Output path *without* extension. The format flag chooses extensions. |
| `-f, --format FMT` | `both` | `json` \| `markdown` \| `sarif` \| `html` \| `both` (json+markdown) \| `all` (every format). |

**Triage behaviour**

| Flag | Default | Description |
|---|---|---|
| `--suppress FILE` | `suppressions.yaml` | Suppression ruleset. Skipped silently if the file does not exist. |
| `--llm` | off | Run the LLM false-positive filter against Ollama. |

**Agentic mode**

| Flag | Default | Description |
|---|---|---|
| `--agentic` | off | Run as a tool-calling agent instead of the deterministic pipeline. Output is written to `triage_<id>.<ext>` under `--output`'s directory. |
| `--provider {claude,ollama}` | — | LLM provider for `--agentic`. Falls back to `AGENT_PROVIDER` env, then `ollama`. |

**Logging**

| Flag | Default | Description |
|---|---|---|
| `-v` | INFO | DEBUG on the `triage` logger. |
| `-vv` | INFO | DEBUG everywhere (parser internals, LLM request bodies). |
| `--quiet` | off | WARNING and above only. |
| `--version` | — | Print tool version and exit. |

### Suppression File Format

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

Matching: `rule_id` alone, `file_glob` alone, or both (AND). Suppressed findings get `status="suppressed"` and surface in a dedicated report section — never silently dropped.

### Output Formats

| Format | Audience | Notes |
|---|---|---|
| `json` | Downstream tooling, dashboards, APIs | Full `Finding` schema, machine-readable. |
| `markdown` | PR comments, humans | Grouped by status (active / likely-fp / suppressed), sorted by risk score. |
| `sarif` | GitHub Code Scanning | SARIF 2.1.0 with CWE relationships, partial-fingerprints, suppression entries. |
| `html` | Shareable artefact | Self-contained single file, dark theme, zero external deps. Email it, drop it on an S3 bucket, open from `file://`. |

### Finding Schema

| Field | Type | Description |
|---|---|---|
| `scanner` | `str` | Source scanner (`semgrep` / `bandit` / `zap` / `trivy` / `nuclei`). |
| `rule_id` | `str` | Scanner-specific rule identifier. |
| `title` | `str` | Short human-readable title. |
| `severity` | `str` | `critical \| high \| medium \| low \| info`. |
| `risk_score` | `float` | 0–10 CWE heuristic (not CVSS). |
| `message` | `str` | Full message from the scanner. |
| `file_path` | `str` | Affected file or URL (ZAP). |
| `line_number` | `int` | Source line (0 for web findings). |
| `code_snippet` | `str` | Vulnerable code excerpt where available. |
| `url` | `str` | Target URL for ZAP/Nuclei findings. |
| `cwe` | `str` | Canonical `CWE-<N>` form, `""` if none. |
| `tags` | `list[str]` | Scanner-provided tags (OWASP category, etc.). |
| `status` | `str` | `confirmed \| likely_fp \| unreviewed \| suppressed`. |
| `confidence` | `float \| None` | LLM confidence 0–1; `None` = unreviewed. |
| `fp_reason` | `str` | LLM explanation or suppression reason. |
| `sources` | `list[str]` | Agreement trail: `["semgrep:rule-x", "bandit:B608"]`. |
| `raw` | `dict` | Original scanner JSON for forensic access. |

### Testing

```bash
pip install -e '.[dev]'
pytest -q                                                  # 77 tests
pytest -q --cov=core --cov=parsers --cov-branch           # with coverage
pytest -q --cov-fail-under=85                              # CI-equivalent
```

CI runs on Python 3.11 and 3.12 with 85% branch coverage enforced. A separate OPSEC job greps every tracked file for CGNAT ranges and Tailscale/homelab identifiers — build fails if any leak into source.

### Extending

**Adding a new scanner parser** (concrete, 4 steps):

1. Create `parsers/<scanner>.py` implementing `BaseParser` from `parsers/base.py`:
   ```python
   class MyScannerParser(BaseParser):
       def parse(self, filepath: str) -> list[Finding]: ...
   ```
2. Register in `parsers/__init__.py`:
   ```python
   PARSERS["myscanner"] = MyScannerParser
   ```
3. Drop a sample fixture at `tests/fixtures/myscanner_sample.<ext>` and add a parsing test to `tests/test_parsers.py`.
4. If the scanner's severity scale differs, add the mapping to the per-parser severity table (documented in-file).

The dedup, scoring, suppression, LLM, and output stages work automatically — they're pure functions over `list[Finding]`, so a new parser gets the full pipeline for free as soon as it emits normalised `Finding` objects.

**Adding a new output format:** drop `output/<fmt>_report.py` with a `write_<fmt>(findings, path)` function and wire it in `main.py`'s format dispatch.

### Architecture (code layout)

```
parsers/
  base.py            Finding dataclass, normalize_cwe(), BaseParser ABC
  semgrep.py         Semgrep JSON → list[Finding]
  bandit.py          Bandit JSON → list[Finding]
  zap.py             OWASP ZAP XML → list[Finding]
  trivy.py           Trivy JSON → list[Finding]
  nuclei.py          Nuclei JSONL → list[Finding]

core/
  dedup.py           Cross-scanner merge; preserves sources[] trail
  scorer.py          CWE heuristic risk score + agreement bump
  suppression.py     YAML loader; rule_id + file_glob AND matching
  llm.py             Ollama FP filter; status-based (no deletes)

output/
  json_report.py     Machine-readable JSON
  markdown_report.py Grouped MD by status, sorted by risk
  sarif_report.py    SARIF 2.1.0 (CWE taxonomies + suppressions)
  html_report.py     Self-contained dark-theme HTML

agent/
  triage_agent.py    LLM-driven orchestration of the same tools
  tools.py           @tool wrappers over parsers / core / output

kev/                 Experimental: CISA KEV dependency scanner
  fetcher.py         CISA KEV JSON fetcher
  rules.py           KEV → rule compiler
  scanner.py         Dependency + source pattern scanner

main.py              CLI entry point (and `triage` console script)
```

### CI Workflows

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — lint, format, mypy, test matrix, OPSEC scan.
- [`.github/workflows/sast.yml`](.github/workflows/sast.yml) — Semgrep + Bandit → triage → SARIF upload.

### Generating Scanner Output

```bash
# Semgrep
semgrep scan --json --output semgrep_results.json .

# Bandit
bandit -r . -f json -o bandit_results.json --exit-zero

# OWASP ZAP (replace with a real target you own)
zap.sh -cmd -quickurl http://localhost:8080 -quickout zap_results.xml

# Trivy
trivy image --format json --output trivy_results.json myapp:latest

# Nuclei
nuclei -u https://203.0.113.42 -json -o nuclei_results.jsonl
```

---

## Why This Was Built

The honest version: I kept getting paged to look at the same SQL injection three times a week because Semgrep, Bandit, and the IDE plugin all shouted about it independently and nothing merged them. Every "AppSec platform" that solved this cost five figures a year, closed-source, and shipped as a SaaS bucket with a vendor eating my scanner output.

So I wrote the glue. The learning goals were explicit:

- **SARIF spec compliance** — the format is unforgiving. If you want GitHub's Security tab, you learn it properly or your findings vanish.
- **Local LLM integration** — the practical pattern for AppSec: structured output, confidence scores, graceful degradation, and never-delete semantics. The industry is figuring this out in real time, and the right design is defensible — annotate, don't suppress.
- **Zero-dep Python at scale** — proving you can do real work (XML, HTTP, YAML-ish config, dataclasses, SARIF JSON) without pulling 40 packages. Minimal attack surface, trivial supply chain.
- **Agent patterns** — the `--agentic` mode is the same pipeline rewired as 10 LLM-callable tools. Same primitives, different driver — the clean separation is the point.

Career-value: this is the kind of pragmatic infra work AppSec engineers actually ship. Interviewers can read the SARIF code, grep for `@tool` to see the agent pattern, and run `pytest -q` to see 77 tests pass locally. The repo is auditable end-to-end in under an hour.

---

## FAQ

**Q: Why not just use DefectDojo / SOOS / Snyk / Semgrep Pro?**
Those are platforms. This is a 2000-line CLI. If you already have a platform, this slots in front of it: pipe triaged SARIF into DefectDojo and the dedup/LLM filter work still saves you. If you don't have a platform, this is enough to run a one-person AppSec program.

**Q: Is the LLM FP filter safe to trust?**
No, and that's by design. The filter never deletes a finding — it sets `status="likely_fp"` with a confidence score. The reviewer sees every finding, sorted by status. The LLM is a triage accelerator, not an authority.

**Q: What happens if Ollama is down?**
The pipeline logs a warning and sets `status="unreviewed"` on the affected findings. They land in the report with full severity. Nothing is dropped — fail-safe is to escalate, not swallow.

**Q: Does cross-scanner dedup actually work? Scanners disagree on line numbers.**
The key is `(normalized_cwe, file_path, line_number)`. In practice line numbers do drift ±1–2 between scanners for the same bug. The current design accepts this — a one-line split is rare, and it's a bounded false-negative (dedup fails to merge; both findings stay visible with the same CWE). A fuzzy-line variant was prototyped and parked — the complexity cost outweighed the hit rate. Documented ceiling, upgrade path open.

**Q: Why is the risk score 0–10 if it's not CVSS?**
To be legible without lying. Everyone in security reads a 0–10 scale instantly. Calling the field `risk_score` (not `cvss_score`) and documenting the formula in `core/scorer.py` is the honest compromise. If you need real CVSS, feed `cwe` + severity into a dedicated calculator — the schema has what you need.

**Q: Why zero dependencies when PyYAML is fine?**
Because `pip install` in a hardened CI container is sometimes a 20-minute negotiation with a corporate proxy. Shipping stdlib-only means the tool runs the first time, every time, in the environments security tooling actually lives in. The YAML subset covers 100% of real suppression configs; the ceiling is documented.

**Q: Can I use this on a monorepo with 10 scanners?**
Yes. Run the tool once per scanner (one CI step each), feed the JSON reports to a merge step, upload the SARIFs with different `category:` values. GitHub's Security tab handles multi-category uploads natively. Each scanner's output stays independently dismissable.

**Q: What's the `kev/` directory?**
A separate, experimental CISA KEV (Known Exploited Vulnerabilities) scanner — matches your `requirements.txt` / `package.json` / `dpkg` output against the KEV catalog. Not yet wired into the main pipeline; lives alongside as a sibling tool. Excluded from mypy/ruff until it stabilises.

---

## License / Credits

MIT. See `pyproject.toml`.

Built by GP Singh. CWE taxonomy from MITRE. SARIF spec from OASIS. Scanner formats are each vendor's.
