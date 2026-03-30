"""CLI entry point for python-package-scanner."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path

from scanner.graph import normalize, parse_pip_environment, parse_uv_lock
from scanner.osv import query_osv
from scanner.report import build_findings, generate_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python-package-scanner",
        description="Scan Python dependencies for vulnerabilities with dependency chain tracing",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "uv", "pip"],
        default="auto",
        help="Detection mode (default: auto)",
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Path to project directory (default: current directory)",
    )
    parser.add_argument(
        "--ignore-ids",
        default="",
        help="Comma-separated vulnerability IDs to ignore",
    )
    parser.add_argument(
        "--ignore-packages",
        default="",
        help="Comma-separated package names to skip",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        dest="output_format",
        help="Output format (default: markdown)",
    )

    args = parser.parse_args(argv)
    project_path = Path(args.path)

    ignore_ids = {s.strip() for s in args.ignore_ids.split(",") if s.strip()}
    ignore_packages = {normalize(s.strip()) for s in args.ignore_packages.split(",") if s.strip()}

    # Detect mode
    mode = args.mode
    if mode == "auto":
        if (project_path / "uv.lock").exists():
            mode = "uv"
        else:
            mode = "pip"

    # Build dependency graph
    if mode == "uv":
        lock_path = project_path / "uv.lock"
        if not lock_path.exists():
            print(f"Error: uv.lock not found at {lock_path}", file=sys.stderr)
            return 1
        try:
            graph = parse_uv_lock(lock_path)
        except tomllib.TOMLDecodeError as exc:
            print(f"Error: malformed uv.lock: {exc}", file=sys.stderr)
            return 1
    else:
        req_path = project_path / "requirements.txt"
        graph = parse_pip_environment(
            requirements_path=req_path if req_path.exists() else None,
        )

    # Query OSV
    packages_to_query = {
        name: (info.name, info.version)
        for name, info in graph.packages.items()
    }
    osv_results = query_osv(
        packages_to_query,
        ignore_ids=ignore_ids,
        ignore_packages=ignore_packages,
    )

    # Print any API errors as warnings
    for err in osv_results.errors:
        print(f"Warning: {err}", file=sys.stderr)

    # Build findings and generate report
    findings = build_findings(
        osv_results.vulnerabilities,
        graph,
        ignore_ids=ignore_ids,
        ignore_packages=ignore_packages,
    )

    if args.output_format == "json":
        output = json.dumps(
            [
                {
                    "package": f.package,
                    "version": f.version,
                    "vulnerability": f.vuln_id,
                    "aliases": f.aliases,
                    "summary": f.summary,
                    "fixed_versions": f.fixed_versions,
                    "chain": f.chain,
                    "status": f.status,
                }
                for f in findings
            ],
            indent=2,
        )
    else:
        output = generate_markdown(findings)

    print(output)

    # Exit code: 1 if active (non-ignored) vulnerabilities found
    active = [f for f in findings if f.status != "ignored"]
    return 1 if active else 0


if __name__ == "__main__":
    sys.exit(main())
