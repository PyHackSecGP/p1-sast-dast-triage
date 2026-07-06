"""NVD API v2.0 client for CVE details and affected version ranges.

Rate limits (no API key): 5 requests per 30 seconds.
Rate limits (with API key): 50 requests per 30 seconds.
Set NVD_API_KEY env var to use a key.

CPE format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
We use versionStartIncluding, versionEndIncluding, versionEndExcluding
from cpeMatch entries to build version range rules.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Any

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE_DIR = Path(__file__).parent.parent / "data" / "nvd_cache"
_RATE_DELAY = 6.5  # seconds between requests (safe for unauthenticated)


def _get_api_key() -> str | None:
    return os.environ.get("NVD_API_KEY")


def get_cve(cve_id: str, force: bool = False) -> dict[str, Any]:
    """Fetch CVE details from NVD with local caching.

    Args:
        cve_id: e.g. "CVE-2024-3094"
        force: bypass cache and re-fetch

    Returns:
        Full NVD response dict for that CVE.
    """
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = _CACHE_DIR / f"{cve_id}.json"

    if not force and cache_path.exists():
        with cache_path.open() as fh:
            return json.load(fh)

    params: dict[str, str] = {"cveId": cve_id}
    api_key = _get_api_key()
    headers = {"User-Agent": "sast-dast-triage/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            data = {}
        else:
            raise

    with cache_path.open("w") as fh:
        json.dump(data, fh, indent=2)

    # Respect rate limit
    if not api_key:
        time.sleep(_RATE_DELAY)

    return data


def extract_version_ranges(nvd_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse NVD CPE data into package + version range dicts.

    Returns a list of dicts, each with:
        vendor, product, version_exact, version_gte, version_lte, version_lt
    """
    packages: list[dict[str, Any]] = []

    for vuln in nvd_data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                _parse_node(node, packages)

    return packages


def _parse_node(node: dict[str, Any], out: list[dict[str, Any]]) -> None:
    """Recursively extract cpeMatch entries from a config node."""
    for match in node.get("cpeMatch", []):
        if not match.get("vulnerable", False):
            continue

        cpe = match.get("criteria", "")
        parts = cpe.split(":")
        if len(parts) < 6:
            continue

        # cpe:2.3:type:vendor:product:version:...
        cpe_type = parts[2]   # 'a' = application, 'o' = OS, 'h' = hardware
        vendor = parts[3]
        product = parts[4]
        version = parts[5]

        out.append({
            "cpe_type": cpe_type,
            "vendor": vendor,
            "product": product,
            "version_exact": version if version not in ("*", "-") else None,
            "version_gte": match.get("versionStartIncluding"),
            "version_lte": match.get("versionEndIncluding"),
            "version_lt": match.get("versionEndExcluding"),
        })

    for child in node.get("children", []):
        _parse_node(child, out)


def batch_fetch(cve_ids: list[str], verbose: bool = False) -> dict[str, dict[str, Any]]:
    """Fetch multiple CVEs, skipping already-cached ones.

    Returns {cve_id: nvd_data}.
    """
    results: dict[str, dict[str, Any]] = {}
    to_fetch = [c for c in cve_ids if not (_CACHE_DIR / f"{c}.json").exists()]

    if verbose and to_fetch:
        print(f"[nvd] Fetching {len(to_fetch)} CVEs from NVD (cached: {len(cve_ids)-len(to_fetch)})")
        if not _get_api_key():
            eta_min = round(len(to_fetch) * _RATE_DELAY / 60, 1)
            print(f"[nvd] No NVD_API_KEY set — estimated {eta_min}m. Set NVD_API_KEY for 10x faster fetch.")

    for i, cve_id in enumerate(cve_ids):
        if verbose and cve_id in to_fetch:
            print(f"[nvd] {i+1}/{len(cve_ids)} {cve_id}", end="\r")
        results[cve_id] = get_cve(cve_id)

    if verbose and to_fetch:
        print()

    return results
