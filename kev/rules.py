"""KEV rule model, storage, and generation from CVE + NVD data.

Each rule is stored as a JSON file in rules/<rule_id>.json.
Rule ID format: KEV-<CVE-ID>  e.g. KEV-CVE-2024-3094

A rule contains:
  - metadata from the CISA KEV entry (vendor, product, severity, ransomware)
  - version_checks: list of {ecosystem, package, version ranges} from NVD CPE
  - pattern_checks: list of {pattern, file_extensions} for code-level detection

Version checks let the scanner compare installed package versions.
Pattern checks let the scanner grep source code for vulnerable patterns.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_RULES_DIR = Path(__file__).parent.parent / "rules"

# Maps common NVD CPE vendor:product combos to pip/npm package names.
# The NVD uses its own naming; real package manager names differ.
_CPE_TO_PIP: dict[str, str] = {
    "log4j_project:log4j": "log4j",
    "apache:log4j": "log4j",
    "python-pillow:pillow": "pillow",
    "psf:requests": "requests",
    "requests_project:requests": "requests",
    "aiohttp_project:aiohttp": "aiohttp",
    "pycrypto:pycryptodome": "pycryptodome",
    "cryptography:cryptography": "cryptography",
    "paramiko_project:paramiko": "paramiko",
    "jinja2:jinja2": "jinja2",
    "flask:flask": "flask",
    "django:django": "django",
    "pallets:flask": "flask",
    "djangoproject:django": "django",
    "sqlalchemy:sqlalchemy": "sqlalchemy",
    "openssl:openssl": "pyopenssl",
    "zlib:zlib": "zlib",
    "libexpat:expat": "pyexpat",
    "xz_utils_project:xz_utils": "xz-utils",
    "tukaani:xz": "xz-utils",
}

_CPE_TO_NPM: dict[str, str] = {
    "nodejs:node.js": "node",
    "expressjs:express": "express",
    "lodash:lodash": "lodash",
    "moment:moment": "moment",
    "axios:axios": "axios",
    "log4js:log4js": "log4js",
    "jsonwebtoken_project:jsonwebtoken": "jsonwebtoken",
    "webpack:webpack": "webpack",
    "minimist_project:minimist": "minimist",
    "handlebars.js_project:handlebars.js": "handlebars",
    "npmjs:tough-cookie": "tough-cookie",
    "semver_project:semver": "semver",
    "ansi_regex_project:ansi-regex": "ansi-regex",
    "followredirects_project:follow-redirects": "follow-redirects",
    "braces_project:braces": "braces",
    "node-fetch_project:node-fetch": "node-fetch",
    "tar_project:tar": "tar",
}


@dataclass
class VersionCheck:
    """Version-based rule: package at version range is vulnerable."""

    ecosystem: str           # python | node | system
    package: str             # exact package name in that ecosystem
    version_exact: list[str] = field(default_factory=list)   # exact vulnerable versions
    version_gte: str | None = None   # vulnerable if >= this
    version_lte: str | None = None   # vulnerable if <= this
    version_lt: str | None = None    # vulnerable if < this

    def as_range_str(self) -> str:
        """Human-readable version range string."""
        parts = []
        if self.version_exact:
            parts.append(f"=={','.join(self.version_exact)}")
        if self.version_gte:
            parts.append(f">={self.version_gte}")
        if self.version_lte:
            parts.append(f"<={self.version_lte}")
        if self.version_lt:
            parts.append(f"<{self.version_lt}")
        return " ".join(parts) if parts else "all versions"


@dataclass
class PatternCheck:
    """Regex pattern to detect vulnerable code usage."""

    pattern: str
    file_extensions: list[str] = field(default_factory=list)   # [".py", ".js"] or [] for all
    description: str = ""


@dataclass
class KevRule:
    """A scan rule derived from a CISA KEV catalog entry."""

    rule_id: str                    # KEV-CVE-XXXX-XXXXX
    cve_id: str
    title: str
    description: str
    vendor: str
    product: str
    required_action: str
    date_added: str
    due_date: str
    severity: str                   # critical | high | medium
    ransomware: bool
    version_checks: list[VersionCheck] = field(default_factory=list)
    pattern_checks: list[PatternCheck] = field(default_factory=list)
    nvd_enriched: bool = False

    # ------------------------------------------------------------------ #
    #  Persistence                                                         #
    # ------------------------------------------------------------------ #

    def save(self) -> None:
        """Write rule to rules/<rule_id>.json."""
        _RULES_DIR.mkdir(exist_ok=True)
        path = _RULES_DIR / f"{self.rule_id}.json"
        with path.open("w") as fh:
            json.dump(asdict(self), fh, indent=2)

    @classmethod
    def load(cls, path: Path) -> "KevRule":
        """Load a rule from a JSON file."""
        with path.open() as fh:
            data = json.load(fh)
        vcs = [VersionCheck(**v) for v in data.pop("version_checks", [])]
        pcs = [PatternCheck(**p) for p in data.pop("pattern_checks", [])]
        return cls(**data, version_checks=vcs, pattern_checks=pcs)

    def exists(self) -> bool:
        return (_RULES_DIR / f"{self.rule_id}.json").exists()


# ------------------------------------------------------------------ #
#  Registry                                                            #
# ------------------------------------------------------------------ #

def list_rules() -> list[KevRule]:
    """Return all saved rules sorted by CVE ID."""
    _RULES_DIR.mkdir(exist_ok=True)
    rules = []
    for p in sorted(_RULES_DIR.glob("KEV-CVE-*.json")):
        try:
            rules.append(KevRule.load(p))
        except Exception:
            pass
    return rules


def rule_count() -> int:
    _RULES_DIR.mkdir(exist_ok=True)
    return len(list(_RULES_DIR.glob("KEV-CVE-*.json")))


# ------------------------------------------------------------------ #
#  Rule generation                                                     #
# ------------------------------------------------------------------ #

def rule_from_kev_entry(entry: dict[str, Any]) -> KevRule:
    """Create a KevRule from a raw CISA KEV entry (no NVD data).

    This produces a rule with metadata only — no version_checks yet.
    Call enrich_with_nvd() to add version ranges.
    """
    cve_id = entry["cveID"]
    product = entry.get("product", "").lower()
    vendor = entry.get("vendorProject", "").lower()
    ransomware = entry.get("knownRansomwareCampaignUse", "").lower() == "known"

    # Basic severity heuristic: ransomware → critical, else high
    severity = "critical" if ransomware else "high"

    return KevRule(
        rule_id=f"KEV-{cve_id}",
        cve_id=cve_id,
        title=entry.get("vulnerabilityName", f"{cve_id} — {vendor} {product}"),
        description=entry.get("shortDescription", ""),
        vendor=vendor,
        product=product,
        required_action=entry.get("requiredAction", ""),
        date_added=entry.get("dateAdded", ""),
        due_date=entry.get("dueDate", ""),
        severity=severity,
        ransomware=ransomware,
    )


def enrich_with_nvd(rule: KevRule, nvd_data: dict[str, Any]) -> KevRule:
    """Add version_checks to a rule using NVD CPE data.

    Mutates rule in place and returns it.
    """
    from .nvd import extract_version_ranges
    packages = extract_version_ranges(nvd_data)

    if not packages:
        return rule

    seen: set[str] = set()

    for pkg in packages:
        vendor = pkg["vendor"]
        product = pkg["product"]
        key = f"{vendor}:{product}"

        # Try ecosystem mappings
        pip_name = _CPE_TO_PIP.get(key) or _CPE_TO_PIP.get(f"{vendor}:{product.replace('_', '-')}")
        npm_name = _CPE_TO_NPM.get(key)

        # Fallback: use product name directly (works for many packages)
        if not pip_name and not npm_name:
            # Use product as-is if it looks like a package name
            pip_name = product.replace("_", "-")

        for eco, pkg_name in [("python", pip_name), ("node", npm_name)]:
            if not pkg_name:
                continue
            dedup_key = f"{eco}:{pkg_name}:{pkg.get('version_gte')}:{pkg.get('version_lt')}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            exact_ver = [pkg["version_exact"]] if pkg.get("version_exact") else []
            vc = VersionCheck(
                ecosystem=eco,
                package=pkg_name.lower(),
                version_exact=exact_ver,
                version_gte=pkg.get("version_gte"),
                version_lte=pkg.get("version_lte"),
                version_lt=pkg.get("version_lt"),
            )
            rule.version_checks.append(vc)

    rule.nvd_enriched = True
    return rule


def generate_pattern_rule(cve_id: str, description: str, product: str) -> PatternCheck | None:
    """Generate a basic code-pattern check from CVE description.

    Uses simple keyword extraction — not LLM-based. Catches obvious cases like
    vulnerable import names, CVE-specific function calls, etc.
    """
    product_clean = re.sub(r"[^a-z0-9_]", "_", product.lower()).strip("_")
    if len(product_clean) < 3:
        return None

    # If the product name looks like an importable module, check for its import
    pattern = rf"(?:import|from)\s+{re.escape(product_clean)}"
    return PatternCheck(
        pattern=pattern,
        file_extensions=[".py"],
        description=f"Import of potentially vulnerable {product} ({cve_id})",
    )
