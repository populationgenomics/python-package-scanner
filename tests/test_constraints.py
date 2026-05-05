"""Tests for scanner.constraints — PyPI metadata fetching."""

from __future__ import annotations

from scanner.constraints import (
    build_marker_env,
    filter_requires_dist,
    parse_requires_dist,
)


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


class TestFilterRequiresDist:
    """Tests for marker-aware filtering of requires_dist entries.

    Locks in the fix for the bug where botocore's two urllib3 variants
    (one for python<3.10, one for python>=3.10) collapsed via setdefault
    into the wrong-marker variant, surfacing a phantom blocker.
    """

    def test_picks_matching_marker_variant(self):
        env = build_marker_env(python_version="3.11")
        deps = filter_requires_dist(
            [
                'urllib3>=1.25.4,<1.27 ; python_version < "3.10"',
                'urllib3>=1.25.4,<3 ; python_version >= "3.10"',
            ],
            env,
        )
        # On py3.11 the >=3.10 variant applies; the <3.10 variant must be
        # dropped so it cannot masquerade as a blocker.
        assert deps == {"urllib3": ">=1.25.4,<3"}

    def test_picks_old_python_variant_on_old_python(self):
        env = build_marker_env(python_version="3.9")
        deps = filter_requires_dist(
            [
                'urllib3>=1.25.4,<1.27 ; python_version < "3.10"',
                'urllib3>=1.25.4,<3 ; python_version >= "3.10"',
            ],
            env,
        )
        assert deps == {"urllib3": ">=1.25.4,<1.27"}

    def test_skips_extras_only(self):
        env = build_marker_env(python_version="3.11")
        deps = filter_requires_dist(
            ["pillow ; extra == 'bokeh'", "numpy>=1.20"],
            env,
        )
        assert deps == {"numpy": ">=1.20"}

    def test_unmarked_entries_pass_through(self):
        env = build_marker_env(python_version="3.11")
        deps = filter_requires_dist(["requests>=2.0", "urllib3<3"], env)
        assert deps == {"requests": ">=2.0", "urllib3": "<3"}

    def test_unparseable_marker_kept_conservatively(self):
        env = build_marker_env(python_version="3.11")
        # An unrecognised marker variable shouldn't silently drop the entry.
        deps = filter_requires_dist(
            ["weirdpkg>=1.0 ; bogus_var == 'xyz'"],
            env,
        )
        assert deps == {"weirdpkg": ">=1.0"}


class TestBuildMarkerEnv:
    def test_overrides_python_version(self):
        env = build_marker_env(python_version="3.10")
        assert env["python_version"] == "3.10"
        assert env["python_full_version"] == "3.10.0"

    def test_no_python_version_uses_default(self):
        env = build_marker_env()
        # Whatever the running interpreter reports — just ensure the key
        # exists so Marker.evaluate() never sees an undefined variable.
        assert "python_version" in env
