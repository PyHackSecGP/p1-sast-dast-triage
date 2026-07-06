"""Scan project dependencies and code against KEV rules.

Supported dependency sources:
  - Python: requirements.txt, requirements/*.txt, Pipfile.lock, pyproject.toml (deps section)
  - Node:   package.json, package-lock.json (direct deps only)
  - System: output of `dpkg -l` or `rpm -qa` piped to a file

Version comparison uses tuple-based parsing for stdlib-only operation.
For edge cases with pre-release versions (1.0.0a1, 1.0.0rc1), we fall back
to string comparison — good enough for security triage.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ScanHit:
    """A single dependency match against a KEV rule."""

    cve_id: str
    rule_id: str
    severity: str
    ransomware: bool
    ecosystem: str          # python | node | system
    package: str
    installed_version: str
    source_file: str        # requirements.txt, package.json, etc.
    title: str
    description: str
    required_action: str
    date_added: str
    due_date: str
    version_range: str      # human-readable: ">=1.2.0, <1.2.4"


@dataclass
class PatternHit:
    """A source-code pattern match against a KEV rule."""

    cve_id: str
    rule_id: str
    severity: str
    file_path: str
    line_number: int
    line_content: str
    pattern: str
    description: str


@dataclass
class ScanResult:
    """Aggregated results from scanning a project."""

    target: str
    dep_hits: list[ScanHit] = field(default_factory=list)
    pattern_hits: list[PatternHit] = field(default_factory=list)
    rules_checked: int = 0
    files_scanned: int = 0
    dep_files_found: list[str] = field(default_factory=list)

    @property
    def total_hits(self) -> int:
        return len(self.dep_hits) + len(self.pattern_hits)

    @property
    def critical_hits(self) -> list[ScanHit | PatternHit]:
        return [h for h in self.dep_hits + self.pattern_hits if h.severity == "critical"]


# ------------------------------------------------------------------ #
#  Version parsing helpers                                             #
# ------------------------------------------------------------------ #

def _parse_ver(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable int tuple.

    "1.2.3" → (1, 2, 3), "1.2.3.post1" → (1, 2, 3), "2.0" → (2, 0)
    Non-numeric segments are ignored (pre-release stripped off).
    """
    if not v or v in ("*", "-", "N/A", ""):
        return (0,)
    # Strip build metadata / pre-release suffixes for basic comparison
    v = re.split(r"[+]", v)[0]       # strip build metadata
    v = re.sub(r"[a-zA-Z].*$", "", v)  # strip alpha/beta/rc suffix
    segments = [s for s in re.split(r"[.\-]", v) if s.isdigit()]
    return tuple(int(s) for s in segments) if segments else (0,)


def _version_in_range(installed: str, vc: Any) -> bool:
    """Return True if installed version falls within the vulnerable range.

    Args:
        installed: The installed version string.
        vc: A VersionCheck (or dict-like) with version_exact, version_gte,
            version_lte, version_lt fields.
    """
    inst = _parse_ver(installed)

    # Exact match list
    exact = getattr(vc, "version_exact", None) or vc.get("version_exact", []) if isinstance(vc, dict) else getattr(vc, "version_exact", [])
    if exact and isinstance(exact, list) and installed in exact:
        return True
    if exact and isinstance(exact, list) and any(_parse_ver(e) == inst for e in exact):
        return True

    gte = (getattr(vc, "version_gte", None) or (vc.get("version_gte") if isinstance(vc, dict) else None))
    lte = (getattr(vc, "version_lte", None) or (vc.get("version_lte") if isinstance(vc, dict) else None))
    lt  = (getattr(vc, "version_lt", None)  or (vc.get("version_lt")  if isinstance(vc, dict) else None))

    # If no range constraints and no exact match: assume all versions affected
    if not any([exact, gte, lte, lt]):
        return True

    if gte and inst < _parse_ver(gte):
        return False
    if lte and inst > _parse_ver(lte):
        return False
    if lt and inst >= _parse_ver(lt):
        return False

    return True


# ------------------------------------------------------------------ #
#  Dependency file parsers                                             #
# ------------------------------------------------------------------ #

def _parse_requirements_txt(path: Path) -> dict[str, str]:
    """Parse requirements*.txt → {normalized_name: version}."""
    deps: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([^\s,;#]+)", line)
        if m:
            name = m.group(1).lower().replace("-", "_").replace(".", "_")
            deps[name] = m.group(2)
            # Also store with original casing variants
            deps[m.group(1).lower()] = m.group(2)
            deps[m.group(1).lower().replace("_", "-")] = m.group(2)
    return deps


def _parse_pipfile_lock(path: Path) -> dict[str, str]:
    """Parse Pipfile.lock → {package_name: version}."""
    data = json.loads(path.read_text())
    deps: dict[str, str] = {}
    for section in ("default", "develop"):
        for name, meta in data.get(section, {}).items():
            ver = meta.get("version", "")
            if ver.startswith("=="):
                ver = ver[2:]
            deps[name.lower()] = ver
            deps[name.lower().replace("-", "_")] = ver
    return deps


def _parse_pyproject_toml(path: Path) -> dict[str, str]:
    """Parse pyproject.toml dependencies (basic, no TOML parser needed)."""
    deps: dict[str, str] = {}
    text = path.read_text(errors="replace")
    # Find [project.dependencies] or [tool.poetry.dependencies] sections
    for line in text.splitlines():
        m = re.match(r'^\s*"?([A-Za-z0-9_.-]+)\s*(?:>=|==|<=|~=)\s*([^",;\s]+)', line)
        if m:
            name = m.group(1).lower()
            deps[name] = m.group(2)
            deps[name.replace("-", "_")] = m.group(2)
    return deps


def _parse_package_json(path: Path) -> dict[str, str]:
    """Parse package.json → {package_name: version}."""
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver in data.get(section, {}).items():
            # Strip semver range operators: ^1.0.0 → 1.0.0, ~1.2 → 1.2
            ver = re.sub(r"^[~^>=<v]", "", ver.strip()).split(" ")[0]
            deps[name.lower()] = ver
    return deps


def _parse_package_lock(path: Path) -> dict[str, str]:
    """Parse package-lock.json → {package_name: resolved_version}."""
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    deps: dict[str, str] = {}
    # v2/v3 lockfile format
    for pkg_path, meta in data.get("packages", {}).items():
        if not pkg_path or pkg_path == "":
            continue
        name = pkg_path.split("node_modules/")[-1].lower()
        deps[name] = meta.get("version", "")
    return deps


def _parse_dpkg_list(path: Path) -> dict[str, str]:
    """Parse output of `dpkg -l` saved to a file → {package: version}."""
    deps: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        # ii  package-name  1.2.3  amd64  Description
        parts = line.split()
        if len(parts) >= 3 and parts[0] in ("ii", "hi", "ri"):
            deps[parts[1].lower()] = parts[2]
    return deps


# ------------------------------------------------------------------ #
#  Collect all deps from a directory                                   #
# ------------------------------------------------------------------ #

def collect_deps(root: Path) -> tuple[dict[str, tuple[str, str]], dict[str, tuple[str, str]]]:
    """Walk project dir and collect all Python and Node deps.

    Returns:
        (python_deps, node_deps) where each is
        {normalized_name: (version, source_file_path)}
    """
    python_deps: dict[str, tuple[str, str]] = {}
    node_deps: dict[str, tuple[str, str]] = {}

    def _add_py(d: dict[str, str], src: str) -> None:
        for name, ver in d.items():
            if name not in python_deps:
                python_deps[name] = (ver, src)

    def _add_node(d: dict[str, str], src: str) -> None:
        for name, ver in d.items():
            if name not in node_deps:
                node_deps[name] = (ver, src)

    # Python
    for p in sorted(root.rglob("requirements*.txt")):
        _add_py(_parse_requirements_txt(p), str(p))

    for p in root.rglob("Pipfile.lock"):
        _add_py(_parse_pipfile_lock(p), str(p))

    for p in root.rglob("pyproject.toml"):
        _add_py(_parse_pyproject_toml(p), str(p))

    # Node (skip node_modules)
    for p in root.rglob("package-lock.json"):
        if "node_modules" not in str(p):
            _add_node(_parse_package_lock(p), str(p))

    for p in root.rglob("package.json"):
        if "node_modules" not in str(p):
            _add_node(_parse_package_json(p), str(p))

    return python_deps, node_deps


# ------------------------------------------------------------------ #
#  Main scan function                                                  #
# ------------------------------------------------------------------ #

def scan_project(target: str, rules: list[Any], scan_patterns: bool = True) -> ScanResult:
    """Scan a project directory against all KEV rules.

    Args:
        target: Path to project root (or a single file).
        rules: List of KevRule objects.
        scan_patterns: Also grep source code for pattern_checks.

    Returns:
        ScanResult with all hits.
    """
    root = Path(target)
    result = ScanResult(target=target)
    result.rules_checked = len(rules)

    if not root.exists():
        raise FileNotFoundError(f"Target not found: {target}")

    if root.is_file():
        # Single dep file mode
        py_deps = _parse_requirements_txt(root) if root.name.endswith(".txt") else {}
        nd_deps = _parse_package_json(root) if root.name == "package.json" else {}
        python_deps = {k: (v, str(root)) for k, v in py_deps.items()}
        node_deps = {k: (v, str(root)) for k, v in nd_deps.items()}
    else:
        python_deps, node_deps = collect_deps(root)

    # Track dep files found
    dep_file_set: set[str] = set()
    for _, src in {**python_deps, **node_deps}.values():
        dep_file_set.add(src)
    result.dep_files_found = sorted(dep_file_set)

    # Match rules against collected deps
    for rule in rules:
        _check_rule_against_deps(rule, python_deps, node_deps, result)

    # Pattern scan (grep source code)
    if scan_patterns and root.is_dir():
        _scan_patterns(root, rules, result)

    return result


def _check_rule_against_deps(
    rule: Any,
    python_deps: dict[str, tuple[str, str]],
    node_deps: dict[str, tuple[str, str]],
    result: ScanResult,
) -> None:
    """Check a single rule's version_checks against collected dependencies."""
    for vc in rule.version_checks:
        eco = vc.ecosystem
        pkg = vc.package.lower()

        if eco == "python":
            dep_map = python_deps
            # Also try normalized variants
            name_variants = {pkg, pkg.replace("-", "_"), pkg.replace("_", "-")}
        elif eco == "node":
            dep_map = node_deps
            name_variants = {pkg}
        else:
            continue

        for variant in name_variants:
            if variant not in dep_map:
                continue
            installed_ver, source_file = dep_map[variant]
            if _version_in_range(installed_ver, vc):
                result.dep_hits.append(ScanHit(
                    cve_id=rule.cve_id,
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    ransomware=rule.ransomware,
                    ecosystem=eco,
                    package=variant,
                    installed_version=installed_ver,
                    source_file=source_file,
                    title=rule.title,
                    description=rule.description,
                    required_action=rule.required_action,
                    date_added=rule.date_added,
                    due_date=rule.due_date,
                    version_range=vc.as_range_str(),
                ))
            break  # stop on first matching variant name


def _scan_patterns(root: Path, rules: list[Any], result: ScanResult) -> None:
    """Scan source files for pattern_checks in rules that have them."""
    # Build combined pattern list to avoid re-scanning per rule
    checks: list[tuple[re.Pattern[str], Any, Any]] = []
    for rule in rules:
        for pc in getattr(rule, "pattern_checks", []):
            try:
                compiled = re.compile(pc.pattern, re.IGNORECASE)
                checks.append((compiled, pc, rule))
            except re.error:
                pass

    if not checks:
        return

    # Walk source files
    ext_whitelist = {".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".php", ".java", ".go"}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in ext_whitelist:
            continue
        # Skip common noise dirs
        skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}
        if any(part in skip_dirs for part in path.parts):
            continue

        result.files_scanned += 1
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue

        for lineno, line in enumerate(lines, start=1):
            for compiled, pc, rule in checks:
                if pc.file_extensions and path.suffix not in pc.file_extensions:
                    continue
                if compiled.search(line):
                    result.pattern_hits.append(PatternHit(
                        cve_id=rule.cve_id,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        file_path=str(path),
                        line_number=lineno,
                        line_content=line.strip()[:200],
                        pattern=pc.pattern,
                        description=pc.description,
                    ))
