"""Monitor CISA KEV for new entries and auto-create rules.

How it works:
  1. Fetch current KEV catalog.
  2. Diff against previous snapshot (stored in data/kev_prev.json).
  3. For each new CVE, generate a KevRule from KEV metadata.
  4. Optionally enrich with NVD CPE data for version ranges.
  5. Save rule to rules/KEV-<CVE-ID>.json.
  6. Save new snapshot as baseline.

Run once:  python main.py kev monitor --once
Run loop:  python main.py kev monitor --interval 3600
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from .fetcher import diff_new_entries, fetch_kev
from .nvd import batch_fetch, extract_version_ranges
from .rules import KevRule, enrich_with_nvd, rule_from_kev_entry


def sync_rules(
    force_all: bool = False,
    enrich_nvd: bool = True,
    verbose: bool = True,
) -> list[KevRule]:
    """Sync KEV catalog → generate rules for all new/missing entries.

    Args:
        force_all:  Regenerate rules even for CVEs that already have one.
        enrich_nvd: Fetch NVD CPE data and add version_checks to each rule.
        verbose:    Print progress.

    Returns:
        List of newly created/updated KevRule objects.
    """
    if verbose:
        print("[kev] Fetching CISA KEV catalog...")
    data = fetch_kev()
    new_entries = diff_new_entries(data)

    if not force_all:
        # Filter to only entries that don't have a rule yet
        new_entries = [e for e in new_entries if not KevRule(
            rule_id=f"KEV-{e['cveID']}", cve_id=e["cveID"],
            title="", description="", vendor="", product="",
            required_action="", date_added="", due_date="",
            severity="", ransomware=False,
        ).exists()]

    if not new_entries:
        if verbose:
            print("[kev] No new CVEs — all rules up to date.")
        return []

    if verbose:
        print(f"[kev] {len(new_entries)} new CVE(s) to process.")

    rules: list[KevRule] = []
    nvd_cache: dict[str, Any] = {}

    if enrich_nvd and new_entries:
        cve_ids = [e["cveID"] for e in new_entries]
        if verbose:
            print(f"[kev] Fetching NVD data for {len(cve_ids)} CVE(s)...")
        nvd_cache = batch_fetch(cve_ids, verbose=verbose)

    for entry in new_entries:
        cve_id = entry["cveID"]
        rule = rule_from_kev_entry(entry)

        if enrich_nvd and cve_id in nvd_cache:
            rule = enrich_with_nvd(rule, nvd_cache[cve_id])

        rule.save()
        rules.append(rule)

        if verbose:
            ransomware_tag = " [RANSOMWARE]" if rule.ransomware else ""
            nvd_tag = f" ({len(rule.version_checks)} version checks)" if rule.version_checks else ""
            print(f"  + {cve_id}{ransomware_tag}{nvd_tag}")

    if verbose:
        print(f"[kev] Created {len(rules)} new rule(s). Total rules: {_count_rules()}")

    return rules


def _count_rules() -> int:
    from .rules import rule_count
    return rule_count()


def run_monitor(interval_seconds: int = 3600, verbose: bool = True) -> None:
    """Continuously monitor KEV and auto-create rules for new entries.

    Args:
        interval_seconds: How often to check (default 1 hour).
        verbose: Print status updates.
    """
    if verbose:
        print(f"[kev] Monitor started — checking every {interval_seconds}s. Ctrl+C to stop.")

    while True:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if verbose:
            print(f"\n[{ts}] Checking CISA KEV for new entries...")

        try:
            new_rules = sync_rules(verbose=verbose)
            if new_rules and verbose:
                _print_new_rule_alert(new_rules)
        except Exception as exc:
            print(f"[kev] ERROR: {exc}")

        if verbose:
            print(f"[kev] Next check in {interval_seconds}s...")
        time.sleep(interval_seconds)


def _print_new_rule_alert(rules: list[KevRule]) -> None:
    """Print a formatted alert for newly added KEV entries."""
    print("\n" + "!" * 60)
    print(f"  CISA KEV ALERT: {len(rules)} new actively-exploited CVE(s)")
    print("!" * 60)
    for r in rules:
        ransomware = " *** RANSOMWARE CAMPAIGNS ***" if r.ransomware else ""
        print(f"  {r.cve_id}: {r.title}{ransomware}")
        if r.due_date:
            print(f"    Due (FCEB): {r.due_date}")
        print(f"    Action: {r.required_action}")
        if r.version_checks:
            print(f"    Affected packages: {', '.join(set(vc.package for vc in r.version_checks))}")
    print("!" * 60)
    print("  Run: python main.py kev scan <your-project-path>")
    print("!" * 60 + "\n")
