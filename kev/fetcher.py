"""Download and cache the CISA KEV catalog.

KEV = Known Exploited Vulnerabilities catalog. CISA updates it multiple times
per week. We cache locally and diff against the previous snapshot to detect
new entries for auto-rule generation.
"""
from __future__ import annotations

import json
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_DATA_DIR = Path(__file__).parent.parent / "data"
_CACHE_FILE = _DATA_DIR / "kev_catalog.json"
_PREV_FILE = _DATA_DIR / "kev_prev.json"
_CACHE_TTL_HOURS = 6


def fetch_kev(force: bool = False) -> dict[str, Any]:
    """Return the KEV catalog dict, using local cache if fresh.

    Args:
        force: Skip cache TTL check and always re-download.

    Returns:
        Parsed KEV JSON: keys catalogVersion, dateReleased, count, vulnerabilities.
    """
    _DATA_DIR.mkdir(exist_ok=True)

    if not force and _CACHE_FILE.exists():
        age_h = (time.time() - _CACHE_FILE.stat().st_mtime) / 3600
        if age_h < _CACHE_TTL_HOURS:
            with _CACHE_FILE.open() as fh:
                return json.load(fh)

    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "sast-dast-triage/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())

    with _CACHE_FILE.open("w") as fh:
        json.dump(data, fh, indent=2)

    return data


def as_lookup(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Convert KEV vulnerabilities list to {cve_id: entry} dict."""
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def diff_new_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return KEV entries added since the last saved snapshot.

    Saves the current catalog as the new baseline after diffing.
    First call (no previous snapshot) returns all entries.
    """
    _DATA_DIR.mkdir(exist_ok=True)
    current = as_lookup(data)

    if _PREV_FILE.exists():
        with _PREV_FILE.open() as fh:
            prev = as_lookup(json.load(fh))
        new_ids = set(current) - set(prev)
        new_entries = [current[cid] for cid in sorted(new_ids)]
    else:
        new_entries = list(current.values())

    with _PREV_FILE.open("w") as fh:
        json.dump(data, fh, indent=2)

    return new_entries


def kev_stats(data: dict[str, Any]) -> dict[str, Any]:
    """Return summary statistics about the catalog."""
    vulns = data.get("vulnerabilities", [])
    ransomware_count = sum(
        1 for v in vulns if v.get("knownRansomwareCampaignUse", "").lower() == "known"
    )
    by_year: dict[str, int] = {}
    for v in vulns:
        year = v.get("cveID", "CVE-0000")[:8].split("-")[1] if "-" in v.get("cveID", "") else "?"
        by_year[year] = by_year.get(year, 0) + 1

    return {
        "total": len(vulns),
        "ransomware_associated": ransomware_count,
        "catalog_version": data.get("catalogVersion", "N/A"),
        "date_released": data.get("dateReleased", "N/A"),
        "by_year": dict(sorted(by_year.items())),
    }
