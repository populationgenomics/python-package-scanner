"""Tests for scanner.cli — end-to-end wiring."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from scanner.cli import main
from scanner.osv import OsvResults, Vulnerability

FIXTURES = Path(__file__).parent / "fixtures"


def _mock_osv_no_vulns(*args, **kwargs):
    return OsvResults()


def _mock_osv_with_vulns(*args, **kwargs):
    return OsvResults(
        vulnerabilities=[
            Vulnerability(
                id="GHSA-test",
                aliases=["CVE-2024-0001"],
                summary="Test vulnerability",
                fixed_versions=["2.3.8"],
                package="werkzeug",
                installed_version="2.3.0",
            )
        ]
    )


class TestCli:
    @patch("scanner.cli.query_osv", side_effect=_mock_osv_no_vulns)
    def test_uv_mode_clean(self, mock_osv, capsys):
        exit_code = main(["--mode", "uv", "--path", str(FIXTURES)])
        assert exit_code == 0
        output = capsys.readouterr().out
        assert "No vulnerabilities found" in output

    @patch("scanner.cli.query_osv", side_effect=_mock_osv_with_vulns)
    def test_uv_mode_with_vulns(self, mock_osv, capsys):
        exit_code = main(["--mode", "uv", "--path", str(FIXTURES)])
        assert exit_code == 1
        output = capsys.readouterr().out
        assert "werkzeug" in output
        assert "CVE-2024-0001" in output

    @patch("scanner.cli.query_osv", side_effect=_mock_osv_no_vulns)
    def test_auto_detects_uv(self, mock_osv, capsys):
        # fixtures/ has uv.lock, so auto should pick uv mode
        exit_code = main(["--path", str(FIXTURES)])
        assert exit_code == 0

    @patch("scanner.cli.query_osv", side_effect=_mock_osv_with_vulns)
    def test_json_output(self, mock_osv, capsys):
        exit_code = main(["--mode", "uv", "--path", str(FIXTURES), "--format", "json"])
        assert exit_code == 1
        output = capsys.readouterr().out
        data = json.loads(output)
        assert len(data) == 1
        assert data[0]["package"] == "werkzeug"
        assert data[0]["vulnerability"] == "GHSA-test"

    @patch("scanner.cli.query_osv", side_effect=_mock_osv_with_vulns)
    def test_ignore_ids(self, mock_osv, capsys):
        exit_code = main([
            "--mode", "uv",
            "--path", str(FIXTURES),
            "--ignore-ids", "GHSA-test",
        ])
        # Vuln is still returned by OSV mock but ignored in findings
        assert exit_code == 0

    def test_missing_uv_lock(self, tmp_path, capsys):
        exit_code = main(["--mode", "uv", "--path", str(tmp_path)])
        assert exit_code == 1
        err = capsys.readouterr().err
        assert "uv.lock not found" in err

    @patch("scanner.cli.query_osv", side_effect=_mock_osv_with_vulns)
    def test_ignore_packages(self, mock_osv, capsys):
        exit_code = main([
            "--mode", "uv",
            "--path", str(FIXTURES),
            "--ignore-packages", "werkzeug",
        ])
        assert exit_code == 0

    def test_malformed_uv_lock(self, tmp_path, capsys):
        (tmp_path / "uv.lock").write_text("not valid toml {{{{")
        exit_code = main(["--mode", "uv", "--path", str(tmp_path)])
        assert exit_code == 1
        err = capsys.readouterr().err
        assert "malformed uv.lock" in err

    @patch("scanner.cli.query_osv", side_effect=_mock_osv_no_vulns)
    def test_empty_uv_lock(self, mock_osv, tmp_path, capsys):
        (tmp_path / "uv.lock").write_text("")
        exit_code = main(["--mode", "uv", "--path", str(tmp_path)])
        assert exit_code == 0

    @patch("scanner.cli.query_osv")
    def test_osv_errors_warned(self, mock_osv, capsys):
        from scanner.osv import OsvResults

        mock_osv.return_value = OsvResults(errors=["OSV API error after retry: timeout"])
        exit_code = main(["--mode", "uv", "--path", str(FIXTURES)])
        assert exit_code == 0
        err = capsys.readouterr().err
        assert "Warning:" in err
