"""Markdown report generation for vulnerability scan results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.graph import DependencyGraph
    from scanner.osv import Vulnerability


@dataclass
class Finding:
    package: str
    version: str
    vuln_id: str
    aliases: list[str]
    summary: str
    fixed_versions: list[str]
    chain: list[str]
    status: str  # "fixable", "blocked", "ignored"


def build_findings(
    vulnerabilities: list[Vulnerability],
    graph: DependencyGraph,
    ignore_ids: set[str] | None = None,
    ignore_packages: set[str] | None = None,
) -> list[Finding]:
    """Combine vulnerability data with dependency chain information."""
    ignore_ids = ignore_ids or set()
    ignore_packages = ignore_packages or set()
    findings: list[Finding] = []

    for vuln in vulnerabilities:
        # Skip if ignored
        all_ids = {vuln.id} | set(vuln.aliases)
        if all_ids & ignore_ids:
            status = "ignored"
        elif vuln.package in ignore_packages:
            status = "ignored"
        elif vuln.fixed_versions:
            # Has a fix available — check if chain is blocked
            chain = graph.trace_chain(vuln.package)
            if _is_chain_blocked(chain, graph):
                status = "blocked"
            else:
                status = "fixable"
        else:
            status = "blocked"

        chain = graph.trace_chain(vuln.package)

        findings.append(
            Finding(
                package=vuln.package,
                version=vuln.installed_version,
                vuln_id=vuln.id,
                aliases=vuln.aliases,
                summary=vuln.summary,
                fixed_versions=vuln.fixed_versions,
                chain=chain,
                status=status,
            )
        )

    return findings


def _is_chain_blocked(chain: list[str], graph: DependencyGraph) -> bool:
    """Check if the dependency chain suggests a fix is blocked.

    A chain is "blocked" if the direct dependency (chain[0]) is the vulnerable
    package itself and has no parent that could be upgraded, or if the direct
    dep pins a version that can't be changed.

    For now, we consider a chain blocked only if the vulnerable package IS
    the direct dependency (nothing upstream to upgrade).
    """
    return len(chain) == 1


def generate_markdown(findings: list[Finding]) -> str:
    """Generate a markdown vulnerability report."""
    if not findings:
        return "## Vulnerability Audit\n\nNo vulnerabilities found."

    active = [f for f in findings if f.status != "ignored"]
    ignored = [f for f in findings if f.status == "ignored"]

    total = len(active)
    unique_packages = len({f.package for f in active})

    lines: list[str] = []
    lines.append("## Vulnerability Audit")
    lines.append("")
    lines.append(f"Found {total} vulnerabilities in {unique_packages} packages")
    lines.append("")
    lines.append("| Package | Version | Vulnerability | Fix | Dependency Chain |")
    lines.append("|---------|---------|--------------|-----|------------------|")

    for f in sorted(active, key=lambda x: (x.package, x.vuln_id)):
        vuln_display = f.vuln_id
        if f.aliases:
            cves = [a for a in f.aliases if a.startswith("CVE-")]
            if cves:
                vuln_display = cves[0]

        fix_display = ", ".join(f.fixed_versions) if f.fixed_versions else "None"

        chain_display = _format_chain(f.chain, f.status)

        lines.append(
            f"| {f.package} | {f.version} | {vuln_display} | {fix_display} | {chain_display} |"
        )

    # Summary
    fixable = sum(1 for f in active if f.status == "fixable")
    blocked = sum(1 for f in active if f.status == "blocked")

    lines.append("")
    lines.append("### Summary")
    if fixable:
        lines.append(f"- {fixable} fixable via dependency upgrade")
    if blocked:
        lines.append(f"- {blocked} blocked by upstream constraints")
    if ignored:
        lines.append(f"- {len(ignored)} ignored")

    return "\n".join(lines)


def _format_chain(chain: list[str], status: str) -> str:
    """Format a dependency chain for display."""
    if len(chain) <= 1:
        pkg = chain[0] if chain else "unknown"
        if status == "blocked":
            return f"**{pkg}** (pinned, blocked)"
        return pkg

    return " > ".join(chain)
