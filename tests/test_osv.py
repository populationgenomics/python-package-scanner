"""Tests for scanner.osv — OSV.dev API client."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from scanner.osv import (
    _extract_fixed_versions,
    query_osv,
)


def _make_vuln_detail(
    vuln_id: str = "GHSA-1234",
    aliases: list[str] | None = None,
    summary: str = "Test vulnerability",
    package_name: str = "foo",
    introduced: str = "0",
    fixed: str | None = "2.0.0",
) -> dict:
    """Build a full OSV vulnerability detail."""
    events = [{"introduced": introduced}]
    if fixed:
        events.append({"fixed": fixed})
    return {
        "id": vuln_id,
        "aliases": aliases or [],
        "summary": summary,
        "affected": [
            {
                "package": {"name": package_name, "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
    }


def _mock_urlopen_factory(responses: dict[str, dict]):
    """Create urlopen mock that returns different data per package name.

    responses: mapping of package_name -> query response
    """
    def mock_urlopen(req, **kwargs):
        body = json.loads(req.data)
        pkg_name = body.get("package", {}).get("name", "")
        resp_data = responses.get(pkg_name, {})

        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps(resp_data).encode()
        return mock_resp

    return mock_urlopen


class TestQueryOsv:
    @patch("scanner.osv.urllib.request.urlopen")
    def test_basic_query(self, mock_urlopen):
        responses = {
            "werkzeug": {
                "vulns": [
                    _make_vuln_detail(
                        "GHSA-abcd", ["CVE-2024-0001"],
                        package_name="werkzeug", fixed="2.4.0",
                    )
                ]
            },
            "flask": {},  # no vulns
        }
        mock_urlopen.side_effect = _mock_urlopen_factory(responses)

        results = query_osv({
            "werkzeug": ("werkzeug", "2.3.0"),
            "flask": ("flask", "2.3.0"),
        })

        assert len(results.vulnerabilities) == 1
        v = results.vulnerabilities[0]
        assert v.id == "GHSA-abcd"
        assert v.aliases == ["CVE-2024-0001"]
        assert v.package == "werkzeug"
        assert v.installed_version == "2.3.0"
        assert v.fixed_versions == ["2.4.0"]

    @patch("scanner.osv.urllib.request.urlopen")
    def test_version_sent_as_top_level_field(self, mock_urlopen):
        """Verify the version is a top-level field, not nested under package."""
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({}).encode()
        mock_urlopen.return_value = mock_resp

        query_osv({"foo": ("foo", "1.2.3")})

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        body = json.loads(req.data)
        assert body["version"] == "1.2.3"
        assert "version" not in body["package"]

    @patch("scanner.osv.urllib.request.urlopen")
    def test_no_vulns_returns_clean(self, mock_urlopen):
        mock_urlopen.side_effect = _mock_urlopen_factory({"foo": {}})

        results = query_osv({"foo": ("foo", "2.0.0")})
        assert len(results.vulnerabilities) == 0

    @patch("scanner.osv.urllib.request.urlopen")
    def test_ignore_ids_by_primary(self, mock_urlopen):
        responses = {
            "foo": {"vulns": [_make_vuln_detail("GHSA-abcd", package_name="foo")]},
        }
        mock_urlopen.side_effect = _mock_urlopen_factory(responses)

        results = query_osv({"foo": ("foo", "1.0")}, ignore_ids={"GHSA-abcd"})
        assert len(results.vulnerabilities) == 0

    @patch("scanner.osv.urllib.request.urlopen")
    def test_ignore_ids_by_alias(self, mock_urlopen):
        responses = {
            "foo": {
                "vulns": [
                    _make_vuln_detail("GHSA-abcd", ["CVE-2024-0001"], package_name="foo")
                ]
            },
        }
        mock_urlopen.side_effect = _mock_urlopen_factory(responses)

        results = query_osv({"foo": ("foo", "1.0")}, ignore_ids={"CVE-2024-0001"})
        assert len(results.vulnerabilities) == 0

    @patch("scanner.osv.urllib.request.urlopen")
    def test_ignore_packages(self, mock_urlopen):
        results = query_osv({"foo": ("foo", "1.0")}, ignore_packages={"foo"})
        mock_urlopen.assert_not_called()
        assert len(results.vulnerabilities) == 0

    @patch("scanner.osv.urllib.request.urlopen")
    def test_withdrawn_vulns_skipped(self, mock_urlopen):
        vuln = _make_vuln_detail("GHSA-old", package_name="foo")
        vuln["withdrawn"] = "2024-01-01T00:00:00Z"
        responses = {"foo": {"vulns": [vuln]}}
        mock_urlopen.side_effect = _mock_urlopen_factory(responses)

        results = query_osv({"foo": ("foo", "1.0")})
        assert len(results.vulnerabilities) == 0

    @patch("scanner.osv.urllib.request.urlopen")
    def test_error_captured(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("down")

        results = query_osv({"foo": ("foo", "1.0")})
        assert len(results.errors) == 1

    def test_empty_packages(self):
        results = query_osv({})
        assert len(results.vulnerabilities) == 0
        assert len(results.errors) == 0


class TestExtractFixedVersions:
    def test_basic(self):
        vuln = _make_vuln_detail(package_name="foo", fixed="2.0.0")
        assert _extract_fixed_versions(vuln, "foo") == ["2.0.0"]

    def test_no_fix(self):
        vuln = _make_vuln_detail(package_name="foo", fixed=None)
        assert _extract_fixed_versions(vuln, "foo") == []

    def test_wrong_package(self):
        vuln = _make_vuln_detail(package_name="bar", fixed="2.0.0")
        assert _extract_fixed_versions(vuln, "foo") == []
