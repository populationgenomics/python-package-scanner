"""Markdown report generation for vulnerability scan results."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scanner.specifier import any_satisfies

if TYPE_CHECKING:
    from scanner.constraints import ConstraintsMap, ConstraintsProvider
    from scanner.graph import DependencyGraph
    from scanner.osv import Vulnerability


@dataclass
class BlockingParent:
    """A parent whose version specifier excludes every available fix."""

    name: str
    version: str
    specifier: str


@dataclass
class Finding:
    package: str
    version: str
    vuln_id: str
    aliases: list[str]
    summary: str
    fixed_versions: list[str]
    chain: list[str]
    # Status taxonomy:
    #   "fixable"          — bump in lockfile resolves it
    #   "blocked-direct"   — the vulnerable pkg is itself a direct dep; root
    #                        project's spec excludes the fix (bump pyproject)
    #   "blocked-upstream" — a transitive parent caps the fix; needs upstream
    #                        change or ``[tool.uv] override-dependencies``
    #   "no-fix"           — no fixed version exists yet
    #   "ignored"          — user-suppressed
    status: str
    is_dev: bool = False
    blocking_parents: list[BlockingParent] = field(default_factory=list)


def build_findings(
    vulnerabilities: list[Vulnerability],
    graph: DependencyGraph,
    ignore_ids: set[str] | None = None,
    ignore_packages: set[str] | None = None,
    constraints: ConstraintsMap | None = None,
    constraints_provider: ConstraintsProvider | None = None,
) -> list[Finding]:
    """Combine vulnerability data with dependency-chain and constraint info.

    ``constraints`` is an optional pre-fetched map of ``(parent, version) -> {child: spec}``.
    If absent and ``constraints_provider`` is provided, the provider is invoked
    with the deduplicated list of parents that need querying. If neither is
    given, blocked-upstream classification falls back to in-graph specs only
    (which covers the root project but no transitive caps).
    """
    ignore_ids = ignore_ids or set()
    ignore_packages = ignore_packages or set()

    # First pass: figure out which (parent, version) pairs we need PyPI specs
    # for. Only fetch parents of vulnerable, fixable packages — bounded.
    if constraints is None and constraints_provider is not None:
        wanted = _parents_needing_constraints(vulnerabilities, graph, ignore_ids, ignore_packages)
        constraints = constraints_provider(wanted) if wanted else {}
    constraints = constraints or {}

    findings: list[Finding] = []
    for vuln in vulnerabilities:
        all_ids = {vuln.id} | set(vuln.aliases)
        if all_ids & ignore_ids or vuln.package in ignore_packages:
            findings.append(_finding(vuln, graph, status="ignored"))
            continue
        if not vuln.fixed_versions:
            findings.append(_finding(vuln, graph, status="no-fix"))
            continue

        blocking = _find_blocking_parents(vuln, graph, constraints)
        if blocking:
            chain_len = len(graph.trace_chain(vuln.package))
            status = "blocked-direct" if chain_len == 1 else "blocked-upstream"
            findings.append(_finding(vuln, graph, status=status, blocking=blocking))
        else:
            findings.append(_finding(vuln, graph, status="fixable"))

    return findings


def _finding(
    vuln: Vulnerability,
    graph: DependencyGraph,
    status: str,
    blocking: list[BlockingParent] | None = None,
) -> Finding:
    return Finding(
        package=vuln.package,
        version=vuln.installed_version,
        vuln_id=vuln.id,
        aliases=vuln.aliases,
        summary=vuln.summary,
        fixed_versions=vuln.fixed_versions,
        chain=graph.trace_chain(vuln.package),
        status=status,
        is_dev=graph.is_dev_only(vuln.package),
        blocking_parents=blocking or [],
    )


def _parents_needing_constraints(
    vulnerabilities: list[Vulnerability],
    graph: DependencyGraph,
    ignore_ids: set[str],
    ignore_packages: set[str],
) -> list[tuple[str, str]]:
    """Return the (name, version) parents we need PyPI specs for."""
    wanted: set[tuple[str, str]] = set()
    for vuln in vulnerabilities:
        if not vuln.fixed_versions:
            continue
        if vuln.package in ignore_packages:
            continue
        if ({vuln.id} | set(vuln.aliases)) & ignore_ids:
            continue
        for parent_name in graph.reverse_map.get(vuln.package, []):
            info = graph.packages.get(parent_name)
            if info is None:
                continue
            wanted.add((info.name, info.version))
    return sorted(wanted)


def _find_blocking_parents(
    vuln: Vulnerability,
    graph: DependencyGraph,
    constraints: ConstraintsMap,
) -> list[BlockingParent]:
    """Return parents whose specifier excludes every fixed version of ``vuln``.

    Combines two sources:
      1. In-graph dep_specs (root project + pip-mode installed metadata).
      2. PyPI-fetched constraints for transitive parents.

    The root project's spec on a direct dep is also considered (via
    ``graph.root_specs``) so direct-dep caps in pyproject are surfaced.
    """
    blocking: list[BlockingParent] = []
    fixes = vuln.fixed_versions

    # 1. Root project's spec on this package (only meaningful for direct deps).
    if vuln.package in graph.direct_deps or vuln.package in graph.dev_deps:
        root_spec = graph.root_specs.get(vuln.package, "")
        if root_spec and not any_satisfies(fixes, root_spec):
            blocking.append(BlockingParent(name="(root project)", version="", specifier=root_spec))

    # 2. Each parent in the live graph.
    for parent_name in graph.reverse_map.get(vuln.package, []):
        info = graph.packages.get(parent_name)
        if info is None:
            continue
        # Prefer in-graph spec when available (pip mode), else PyPI fetch.
        spec = info.dep_specs.get(vuln.package, "")
        if not spec:
            spec = constraints.get((info.name, info.version), {}).get(vuln.package, "")
        if not spec:
            continue
        if not any_satisfies(fixes, spec):
            blocking.append(BlockingParent(name=info.name, version=info.version, specifier=spec))
    return blocking


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def generate_markdown(findings: list[Finding]) -> str:
    """Generate a markdown vulnerability report grouped by resolution status."""
    if not findings:
        return "## Vulnerability Audit\n\nNo vulnerabilities found."

    active = [f for f in findings if f.status != "ignored"]
    ignored = [f for f in findings if f.status == "ignored"]

    if not active:
        lines = ["## Vulnerability Audit", "", f"All {len(ignored)} findings ignored."]
        return "\n".join(lines)

    # Group by package + status, summing CVE counts
    runtime = [f for f in active if not f.is_dev]
    dev = [f for f in active if f.is_dev]

    runtime_actionable = _group_by_package([f for f in runtime if f.status == "fixable"])
    runtime_blocked_upstream = _group_by_package(
        [f for f in runtime if f.status == "blocked-upstream"]
    )
    runtime_blocked_direct = _group_by_package(
        [f for f in runtime if f.status == "blocked-direct"]
    )
    runtime_nofix = _group_by_package([f for f in runtime if f.status == "no-fix"])
    dev_grouped = _group_by_package(dev)

    total = len(active)
    unique_packages = len({f.package for f in active})
    actionable_cves = sum(len(g) for g in runtime_actionable.values())
    blocked_cves = sum(len(g) for g in runtime_blocked_upstream.values()) + sum(
        len(g) for g in runtime_blocked_direct.values()
    )
    dev_cves = len(dev)

    lines: list[str] = []
    lines.append("## Vulnerability Audit")
    lines.append("")
    # The "Found N vulnerabilities" prefix is parsed by action.yml to extract
    # the count — keep the digits adjacent to "Found " with no markdown.
    lines.append(f"Found {total} vulnerabilities across {unique_packages} packages.")
    breakdown: list[str] = []
    if actionable_cves:
        breakdown.append(f"**{actionable_cves} actionable now**")
    if blocked_cves:
        breakdown.append(f"{blocked_cves} blocked")
    if dev_cves:
        breakdown.append(f"{dev_cves} in dev-only paths")
    if breakdown:
        lines.append(", ".join(breakdown) + ".")
    lines.append("")

    if runtime_actionable:
        lines += _section_actionable(runtime_actionable)
    if runtime_blocked_upstream:
        lines += _section_blocked_upstream(runtime_blocked_upstream)
    if runtime_blocked_direct:
        lines += _section_blocked_direct(runtime_blocked_direct)
    if dev_grouped:
        lines += _section_dev(dev_grouped)
    if runtime_nofix:
        lines += _section_nofix(runtime_nofix)
    if ignored:
        lines.append(f"_{len(ignored)} finding(s) suppressed via ignore list._")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _group_by_package(findings: list[Finding]) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.package].append(f)
    return dict(sorted(groups.items()))


def _best_fix(findings: list[Finding]) -> str:
    """Pick the highest fixed version across the group's findings."""
    candidates: set[str] = set()
    for f in findings:
        candidates.update(f.fixed_versions)
    if not candidates:
        return "—"
    # Sort by parsed release tuple, falling back to string.
    from scanner.specifier import _parse  # local import to keep public surface small

    return sorted(candidates, key=lambda v: (_parse(v), v))[-1]


def _path_summary(findings: list[Finding]) -> str:
    """Render a representative dependency path for a package's findings."""
    chain = findings[0].chain
    if len(chain) <= 1:
        return f"**{chain[0]}** (direct)"
    return " → ".join(chain)


def _cve_list(findings: list[Finding]) -> str:
    ids: list[str] = []
    for f in findings:
        cve = next((a for a in f.aliases if a.startswith("CVE-")), None)
        ids.append(cve or f.vuln_id)
    # Dedupe preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            unique.append(i)
    if len(unique) <= 3:
        return ", ".join(unique)
    return f"{', '.join(unique[:2])}, +{len(unique) - 2} more"


def _section_actionable(groups: dict[str, list[Finding]]) -> list[str]:
    lines = ["### Actionable now — bump via `uv.lock`", ""]
    lines.append("| Package | Current → Fix | CVEs | Path |")
    lines.append("|---|---|---|---|")
    for pkg, group in groups.items():
        version = group[0].version
        fix = _best_fix(group)
        cves = _cve_list(group)
        path = _path_summary(group)
        lines.append(f"| `{pkg}` | {version} → {fix} | {cves} | {path} |")
    lines.append("")
    lines.append("<details><summary>One-shot fix command</summary>")
    lines.append("")
    lines.append("```bash")
    lines.append("uv lock \\")
    pkgs = list(groups.keys())
    for i, pkg in enumerate(pkgs):
        suffix = " \\" if i < len(pkgs) - 1 else ""
        lines.append(f"  --upgrade-package {pkg}{suffix}")
    lines.append("```")
    lines.append("")
    lines.append("</details>")
    lines.append("")
    return lines


def _section_blocked_upstream(groups: dict[str, list[Finding]]) -> list[str]:
    lines = ["### Blocked upstream — needs a fix in a parent package", ""]
    lines.append("| Package | Current → Fix | CVEs | Blocked by |")
    lines.append("|---|---|---|---|")
    for pkg, group in groups.items():
        version = group[0].version
        fix = _best_fix(group)
        cves = _cve_list(group)
        blockers = _format_blockers(group[0].blocking_parents)
        lines.append(f"| `{pkg}` | {version} → {fix} | {cves} | {blockers} |")
    lines.append("")
    return lines


def _section_blocked_direct(groups: dict[str, list[Finding]]) -> list[str]:
    lines = ["### Pinned direct dependency — bump in `pyproject.toml`", ""]
    lines.append("| Package | Current → Fix | CVEs | Current pin |")
    lines.append("|---|---|---|---|")
    for pkg, group in groups.items():
        version = group[0].version
        fix = _best_fix(group)
        cves = _cve_list(group)
        pin = _format_blockers(group[0].blocking_parents) or "—"
        lines.append(f"| `{pkg}` | {version} → {fix} | {cves} | {pin} |")
    lines.append("")
    return lines


def _section_dev(groups: dict[str, list[Finding]]) -> list[str]:
    lines = ["### Dev-only — not in production image", ""]
    lines.append("| Package | Current → Fix | CVEs | Path |")
    lines.append("|---|---|---|---|")
    for pkg, group in groups.items():
        version = group[0].version
        fix = _best_fix(group) if any(f.fixed_versions for f in group) else "no fix"
        cves = _cve_list(group)
        path = _path_summary(group)
        lines.append(f"| `{pkg}` | {version} → {fix} | {cves} | {path} |")
    lines.append("")
    return lines


def _section_nofix(groups: dict[str, list[Finding]]) -> list[str]:
    lines = ["### No fix available", ""]
    lines.append("| Package | Version | CVEs | Path |")
    lines.append("|---|---|---|---|")
    for pkg, group in groups.items():
        version = group[0].version
        cves = _cve_list(group)
        path = _path_summary(group)
        lines.append(f"| `{pkg}` | {version} | {cves} | {path} |")
    lines.append("")
    return lines


def _format_blockers(blockers: list[BlockingParent]) -> str:
    if not blockers:
        return "—"
    parts: list[str] = []
    for b in blockers:
        if b.version:
            parts.append(f"`{b.name}=={b.version}` pins `{b.specifier}`")
        else:
            parts.append(f"{b.name} pins `{b.specifier}`")
    return "; ".join(parts)
