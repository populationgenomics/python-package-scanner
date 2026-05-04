"""Tests for scanner.report — markdown report generation."""

from __future__ import annotations

from scanner.graph import DependencyGraph, PackageInfo
from scanner.osv import Vulnerability
from scanner.report import (
    BlockingParent,
    Finding,
    build_findings,
    generate_markdown,
)


def _make_graph(root_specs: dict[str, str] | None = None) -> DependencyGraph:
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
        root_specs=root_specs or {},
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

    def test_direct_dep_no_root_pin_is_fixable(self):
        """Direct dep with no root constraint is just a lockfile bump."""
        graph = _make_graph()
        vulns = [_make_vuln("requests", fixed=["3.0.0"])]
        findings = build_findings(vulns, graph)
        assert findings[0].status == "fixable"

    def test_direct_dep_blocked_by_root_pin(self):
        """Direct dep where root pin excludes the fix is blocked-direct."""
        graph = _make_graph(root_specs={"requests": "<3"})
        vulns = [_make_vuln("requests", fixed=["3.0.0"])]
        findings = build_findings(vulns, graph)
        assert findings[0].status == "blocked-direct"
        assert findings[0].blocking_parents
        assert findings[0].blocking_parents[0].specifier == "<3"

    def test_transitive_blocked_by_parent(self):
        """Transitive dep where a parent's spec excludes the fix is blocked-upstream."""
        graph = _make_graph()
        # Pretend werkzeug pins markupsafe<3
        graph.packages["werkzeug"].dep_specs["markupsafe"] = "<3"
        graph.packages["jinja2"].dep_specs["markupsafe"] = ">=2"
        vulns = [_make_vuln("markupsafe", fixed=["3.0.0"])]
        findings = build_findings(vulns, graph)
        assert findings[0].status == "blocked-upstream"
        names = [b.name for b in findings[0].blocking_parents]
        assert "werkzeug" in names

    def test_transitive_unblocked_when_parent_allows_fix(self):
        graph = _make_graph()
        graph.packages["werkzeug"].dep_specs["markupsafe"] = ">=2.0,<4"
        vulns = [_make_vuln("markupsafe", fixed=["3.0.0"])]
        findings = build_findings(vulns, graph)
        assert findings[0].status == "fixable"

    def test_constraints_provider_invoked(self):
        """If in-graph specs are absent, the provider is called for transitive parents."""
        graph = _make_graph()
        calls: list[list[tuple[str, str]]] = []

        def provider(parents: list[tuple[str, str]]) -> dict:
            calls.append(parents)
            # Werkzeug pins markupsafe<3 according to the upstream metadata
            return {("werkzeug", "2.3.0"): {"markupsafe": "<3"}}

        vulns = [_make_vuln("markupsafe", fixed=["3.0.0"])]
        findings = build_findings(vulns, graph, constraints_provider=provider)
        assert calls, "provider should have been called"
        assert ("werkzeug", "2.3.0") in calls[0]
        assert findings[0].status == "blocked-upstream"

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
    def _fixable(self, **kw) -> Finding:
        return Finding(
            package=kw.get("package", "werkzeug"),
            version=kw.get("version", "2.3.0"),
            vuln_id=kw.get("vuln_id", "GHSA-1234"),
            aliases=kw.get("aliases", ["CVE-2024-0001"]),
            summary="Test",
            fixed_versions=kw.get("fixed", ["2.3.8"]),
            chain=kw.get("chain", ["flask", "werkzeug"]),
            status=kw.get("status", "fixable"),
            is_dev=kw.get("is_dev", False),
            blocking_parents=kw.get("blocking", []),
        )

    def test_no_findings(self):
        md = generate_markdown([])
        assert "No vulnerabilities found" in md

    def test_actionable_section(self):
        md = generate_markdown([self._fixable()])
        assert "## Vulnerability Audit" in md
        assert "Found 1 vulnerabilities across 1 packages" in md
        assert "Actionable now" in md
        assert "werkzeug" in md
        assert "CVE-2024-0001" in md
        assert "flask → werkzeug" in md
        assert "uv lock" in md  # one-shot command
        assert "--upgrade-package werkzeug" in md

    def test_blocked_upstream_section(self):
        f = self._fixable(
            package="bokeh",
            version="3.4.3",
            chain=["hail", "bokeh"],
            fixed=["3.8.2"],
            status="blocked-upstream",
            blocking=[BlockingParent(name="hail", version="0.2.137", specifier="<3.5")],
        )
        md = generate_markdown([f])
        assert "Blocked upstream" in md
        assert "`hail==0.2.137`" in md
        assert "<3.5" in md

    def test_blocked_direct_section(self):
        f = self._fixable(
            package="requests",
            version="2.31.0",
            chain=["requests"],
            fixed=["3.0.0"],
            status="blocked-direct",
            blocking=[BlockingParent(name="(root project)", version="", specifier="<3")],
        )
        md = generate_markdown([f])
        assert "Pinned direct dependency" in md
        assert "requests" in md
        assert "<3" in md

    def test_dev_only_section(self):
        f = self._fixable(
            package="pytest", chain=["pytest"], is_dev=True, fixed=["8.5.0"]
        )
        md = generate_markdown([f])
        assert "Dev-only" in md
        assert "pytest" in md

    def test_no_fix_section(self):
        f = self._fixable(
            package="pygments", chain=["mkdocs", "pygments"], fixed=[], status="no-fix"
        )
        md = generate_markdown([f])
        assert "No fix available" in md
        assert "pygments" in md

    def test_ignored_excluded_from_count(self):
        findings = [
            self._fixable(package="a", chain=["x", "a"], fixed=["2.0"]),
            Finding("b", "1.0", "V2", [], "", [], ["b"], "ignored"),
        ]
        md = generate_markdown(findings)
        assert "Found 1 vulnerabilities across 1 packages" in md
        assert "1 finding(s) suppressed" in md

    def test_cve_preferred_over_ghsa(self):
        f = self._fixable(
            package="foo",
            version="1.0",
            vuln_id="GHSA-xxxx",
            aliases=["CVE-2024-9999"],
            chain=["bar", "foo"],
            fixed=["2.0"],
        )
        md = generate_markdown([f])
        assert "CVE-2024-9999" in md
        assert "GHSA-xxxx" not in md

    def test_multiple_cves_listed_in_full(self):
        findings = [
            self._fixable(package="aiohttp", chain=["hail", "aiohttp"], aliases=[f"CVE-2026-{i}"])
            for i in range(5)
        ]
        md = generate_markdown(findings)
        for i in range(5):
            assert f"CVE-2026-{i}" in md
