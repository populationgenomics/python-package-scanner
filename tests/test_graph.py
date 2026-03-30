"""Tests for scanner.graph — uv and pip dependency graph building."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.graph import (
    DependencyGraph,
    PackageInfo,
    _parse_requirements_txt,
    normalize,
    parse_uv_lock,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# normalize()
# ---------------------------------------------------------------------------


class TestNormalize:
    def test_lowercase(self):
        assert normalize("Flask") == "flask"

    def test_underscores(self):
        assert normalize("my_package") == "my-package"

    def test_dots(self):
        assert normalize("zope.interface") == "zope-interface"

    def test_mixed(self):
        assert normalize("My_Cool.Package") == "my-cool-package"

    def test_consecutive_separators(self):
        assert normalize("a--b__c..d") == "a-b-c-d"


# ---------------------------------------------------------------------------
# parse_uv_lock()
# ---------------------------------------------------------------------------


class TestParseUvLock:
    @pytest.fixture()
    def graph(self) -> DependencyGraph:
        return parse_uv_lock(FIXTURES / "uv.lock")

    def test_packages_loaded(self, graph: DependencyGraph):
        # Root project should be excluded, but real packages present
        assert "my-project" not in graph.packages
        assert "flask" in graph.packages
        assert "requests" in graph.packages

    def test_versions(self, graph: DependencyGraph):
        assert graph.packages["flask"].version == "2.3.0"
        assert graph.packages["urllib3"].version == "2.0.7"

    def test_direct_deps(self, graph: DependencyGraph):
        assert graph.direct_deps == {"flask", "requests"}

    def test_direct_flag(self, graph: DependencyGraph):
        assert graph.packages["flask"].is_direct is True
        assert graph.packages["markupsafe"].is_direct is False

    def test_forward_deps(self, graph: DependencyGraph):
        flask_deps = graph.packages["flask"].dependencies
        assert "werkzeug" in flask_deps
        assert "jinja2" in flask_deps

    def test_reverse_map(self, graph: DependencyGraph):
        # markupsafe is required by both jinja2 and werkzeug
        parents = graph.reverse_map.get("markupsafe", [])
        assert "jinja2" in parents
        assert "werkzeug" in parents

    def test_trace_chain_direct(self, graph: DependencyGraph):
        chain = graph.trace_chain("flask")
        assert chain == ["flask"]

    def test_trace_chain_transitive(self, graph: DependencyGraph):
        chain = graph.trace_chain("markupsafe")
        # Should be flask -> jinja2 -> markupsafe OR flask -> werkzeug -> markupsafe
        assert chain[0] == "flask"
        assert chain[-1] == "markupsafe"
        assert len(chain) == 3

    def test_trace_chain_two_levels(self, graph: DependencyGraph):
        chain = graph.trace_chain("urllib3")
        assert chain == ["requests", "urllib3"]

    def test_dev_deps_tracked(self, graph: DependencyGraph):
        assert "pytest" in graph.packages
        assert "pytest" in graph.dev_deps
        assert "pytest" not in graph.direct_deps

    def test_dev_dep_is_dev_only(self, graph: DependencyGraph):
        assert graph.is_dev_only("pytest") is True
        assert graph.is_dev_only("iniconfig") is True  # transitive dev dep

    def test_runtime_dep_not_dev(self, graph: DependencyGraph):
        assert graph.is_dev_only("flask") is False
        assert graph.is_dev_only("werkzeug") is False

    def test_trace_chain_through_dev(self, graph: DependencyGraph):
        chain = graph.trace_chain("iniconfig")
        assert chain[0] == "pytest"
        assert chain[-1] == "iniconfig"

    def test_unknown_package(self, graph: DependencyGraph):
        chain = graph.trace_chain("nonexistent")
        assert chain == ["nonexistent"]


# ---------------------------------------------------------------------------
# Workspace/monorepo uv.lock
# ---------------------------------------------------------------------------


class TestParseUvLockWorkspace:
    @pytest.fixture()
    def graph(self) -> DependencyGraph:
        return parse_uv_lock(FIXTURES / "uv-workspace.lock")

    def test_multiple_roots_excluded(self, graph: DependencyGraph):
        assert "workspace-root" not in graph.packages
        assert "service-a" not in graph.packages
        assert "service-b" not in graph.packages

    def test_direct_deps_from_all_roots(self, graph: DependencyGraph):
        # service-a depends on requests, service-b depends on flask
        assert "requests" in graph.direct_deps
        assert "flask" in graph.direct_deps

    def test_transitive_chain(self, graph: DependencyGraph):
        chain = graph.trace_chain("werkzeug")
        assert chain == ["flask", "werkzeug"]


# ---------------------------------------------------------------------------
# _parse_requirements_txt()
# ---------------------------------------------------------------------------


class TestParseRequirementsTxt:
    def test_basic(self):
        names = _parse_requirements_txt(FIXTURES / "requirements.txt")
        assert names == {"flask", "requests", "cryptography"}

    def test_ignores_comments_and_flags(self, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("# comment\n-r other.txt\nfoo==1.0\nbar\n")
        names = _parse_requirements_txt(req)
        assert names == {"foo", "bar"}


# ---------------------------------------------------------------------------
# DependencyGraph.trace_chain() edge cases
# ---------------------------------------------------------------------------


class TestTraceChainEdgeCases:
    def test_circular_deps(self):
        """trace_chain should not infinite-loop on circular dependencies."""
        packages = {
            "a": PackageInfo(name="a", version="1.0", dependencies=["b"], is_direct=True),
            "b": PackageInfo(name="b", version="1.0", dependencies=["c"]),
            "c": PackageInfo(name="c", version="1.0", dependencies=["a"]),
        }
        reverse_map = {"b": ["a"], "c": ["b"], "a": ["c"]}
        graph = DependencyGraph(
            packages=packages, reverse_map=reverse_map, direct_deps={"a"}
        )
        chain = graph.trace_chain("c")
        assert chain[0] == "a"
        assert chain[-1] == "c"
