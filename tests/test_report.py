"""Tests for scanner.report — markdown report generation."""

from __future__ import annotations

from scanner.graph import DependencyGraph, PackageInfo
from scanner.osv import Vulnerability
from scanner.report import Finding, build_findings, generate_markdown


def _make_graph() -> DependencyGraph:
    """Build a simple test graph: flask -> werkzeug -> markupsafe."""
    packages = {
        "flask": PackageInfo("flask", "2.3.0", ["werkzeug", "jinja2"], is_direct=True),
        "werkzeug": PackageInfo("werkzeug", "2.3.0", ["markupsafe"]),
        "jinja2": PackageInfo("jinja2", "3.1.2", ["markupsafe"]),
        "markupsafe": PackageInfo("markupsafe", "2.1.3", []),
        "requests": PackageInfo("requests", "2.31.0", [], is_direct=True),
    }
    reverse_map = {
        "werkzeug": ["flask"],
        "jinja2": ["flask"],
        "markupsafe": ["jinja2", "werkzeug"],
    }
    return DependencyGraph(
        packages=packages,
        reverse_map=reverse_map,
        direct_deps={"flask", "requests"},
    )


def _make_vuln(
    pkg: str = "werkzeug",
    version: str = "2.3.0",
    vuln_id: str = "GHSA-1234",
    aliases: list[str] | None = None,
    fixed: list[str] | None = None,
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        aliases=aliases or ["CVE-2024-0001"],
        summary="Test vuln",
        fixed_versions=["2.3.8"] if fixed is None else fixed,
        package=pkg,
        installed_version=version,
    )


class TestBuildFindings:
    def test_fixable_transitive(self):
        graph = _make_graph()
        vulns = [_make_vuln("werkzeug")]
        findings = build_findings(vulns, graph)
        assert len(findings) == 1
        assert findings[0].status == "fixable"
        assert findings[0].chain == ["flask", "werkzeug"]

    def test_no_fix_available(self):
        graph = _make_graph()
        vulns = [_make_vuln("werkzeug", fixed=[])]
        findings = build_findings(vulns, graph)
        assert findings[0].status == "no-fix"

    def test_blocked_direct_dep_with_fix(self):
        graph = _make_graph()
        vulns = [_make_vuln("requests", fixed=["3.0.0"])]
        findings = build_findings(vulns, graph)
        # Direct dep with a fix — chain is length 1, so "blocked" (pinned)
        assert findings[0].status == "blocked"

    def test_ignored_by_id(self):
        graph = _make_graph()
        vulns = [_make_vuln("werkzeug")]
        findings = build_findings(vulns, graph, ignore_ids={"GHSA-1234"})
        assert findings[0].status == "ignored"

    def test_ignored_by_alias(self):
        graph = _make_graph()
        vulns = [_make_vuln("werkzeug")]
        findings = build_findings(vulns, graph, ignore_ids={"CVE-2024-0001"})
        assert findings[0].status == "ignored"

    def test_ignored_by_package(self):
        graph = _make_graph()
        vulns = [_make_vuln("werkzeug")]
        findings = build_findings(vulns, graph, ignore_packages={"werkzeug"})
        assert findings[0].status == "ignored"


class TestGenerateMarkdown:
    def test_no_findings(self):
        md = generate_markdown([])
        assert "No vulnerabilities found" in md

    def test_basic_report(self):
        findings = [
            Finding(
                package="werkzeug",
                version="2.3.0",
                vuln_id="GHSA-1234",
                aliases=["CVE-2024-0001"],
                summary="Test",
                fixed_versions=["2.3.8"],
                chain=["flask", "werkzeug"],
                status="fixable",
            )
        ]
        md = generate_markdown(findings)
        assert "## Vulnerability Audit" in md
        assert "1 vulnerabilities in 1 packages" in md
        assert "werkzeug" in md
        assert "CVE-2024-0001" in md
        assert "flask > werkzeug" in md
        assert "1 fixable via dependency upgrade" in md

    def test_pinned_finding(self):
        findings = [
            Finding(
                package="tornado",
                version="6.5.4",
                vuln_id="GHSA-5678",
                aliases=[],
                summary="Test",
                fixed_versions=["6.5.5"],
                chain=["tornado"],
                status="blocked",
            )
        ]
        md = generate_markdown(findings)
        assert "**tornado** (pinned)" in md
        assert "1 pinned" in md

    def test_no_fix_finding(self):
        findings = [
            Finding(
                package="pygments",
                version="2.19.2",
                vuln_id="GHSA-9999",
                aliases=[],
                summary="Test",
                fixed_versions=[],
                chain=["mkdocs", "pygments"],
                status="no-fix",
            )
        ]
        md = generate_markdown(findings)
        assert "no fix available" in md

    def test_ignored_excluded_from_count(self):
        findings = [
            Finding("a", "1.0", "V1", [], "", ["2.0"], ["x", "a"], "fixable"),
            Finding("b", "1.0", "V2", [], "", [], ["b"], "ignored"),
        ]
        md = generate_markdown(findings)
        assert "1 vulnerabilities in 1 packages" in md
        assert "1 ignored" in md

    def test_cve_preferred_over_ghsa(self):
        findings = [
            Finding(
                package="foo",
                version="1.0",
                vuln_id="GHSA-xxxx",
                aliases=["CVE-2024-9999"],
                summary="",
                fixed_versions=["2.0"],
                chain=["bar", "foo"],
                status="fixable",
            )
        ]
        md = generate_markdown(findings)
        assert "CVE-2024-9999" in md
        # GHSA should not appear in the table when a CVE is available
        assert "GHSA-xxxx" not in md
