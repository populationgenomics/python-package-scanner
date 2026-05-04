"""Tests for scanner.constraints — PyPI metadata fetching."""

from __future__ import annotations

from scanner.constraints import parse_requires_dist


class TestParseRequiresDist:
    def test_simple(self):
        name, spec, marker = parse_requires_dist("aiohttp<4,>=3.11.16")
        assert name == "aiohttp"
        assert spec == "<4,>=3.11.16"
        assert marker is None

    def test_parenthesised(self):
        name, spec, marker = parse_requires_dist("azure-identity (>=1.6.0)")
        assert name == "azure-identity"
        assert spec == ">=1.6.0"
        assert marker is None

    def test_with_extras(self):
        name, spec, marker = parse_requires_dist("requests[security] >=2.0")
        assert name == "requests"
        assert spec == ">=2.0"

    def test_with_marker(self):
        name, spec, marker = parse_requires_dist(
            "numpy>=1.20 ; python_version >= '3.10'"
        )
        assert name == "numpy"
        assert spec == ">=1.20"
        assert marker is not None
        assert "python_version" in marker

    def test_extra_marker(self):
        name, spec, marker = parse_requires_dist("pillow ; extra == 'bokeh'")
        assert name == "pillow"
        assert "extra ==" in (marker or "")

    def test_no_spec(self):
        name, spec, marker = parse_requires_dist("colorama")
        assert name == "colorama"
        assert spec == ""

    def test_normalised_name(self):
        name, _, _ = parse_requires_dist("My_Package==1.0")
        assert name == "my-package"

    def test_malformed(self):
        # An empty or weird string returns empty name
        name, _, _ = parse_requires_dist("")
        assert name == ""
