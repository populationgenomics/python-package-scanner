"""OSV.dev API client for querying Python package vulnerabilities."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
TIMEOUT_SECONDS = 10
MAX_WORKERS = 10


@dataclass
class Vulnerability:
    id: str
    aliases: list[str]
    summary: str
    fixed_versions: list[str]
    package: str
    installed_version: str


@dataclass
class OsvResults:
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def query_osv(
    packages: dict[str, tuple[str, str]],
    ignore_ids: set[str] | None = None,
    ignore_packages: set[str] | None = None,
) -> OsvResults:
    """Query OSV.dev for vulnerabilities in the given packages.

    Uses POST /v1/query per package with version as a top-level field
    (same approach as pip-audit). OSV performs server-side version filtering
    and returns only vulns affecting the installed version, with full details.

    Queries run concurrently via ThreadPoolExecutor for speed.

    Args:
        packages: mapping of normalized_name -> (name, version)
        ignore_ids: vulnerability IDs to skip
        ignore_packages: package names to skip entirely

    Returns:
        OsvResults with found vulnerabilities and any errors.
    """
    ignore_ids = ignore_ids or set()
    ignore_packages = ignore_packages or set()

    query_packages = {
        name: (display_name, version)
        for name, (display_name, version) in packages.items()
        if name not in ignore_packages
    }

    if not query_packages:
        return OsvResults()

    results = OsvResults()

    # Query all packages concurrently
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for norm_name, (display_name, version) in query_packages.items():
            future = executor.submit(_query_package, display_name, version)
            futures[future] = (norm_name, display_name, version)

        for future in as_completed(futures):
            norm_name, display_name, version = futures[future]
            try:
                response_data = future.result()
            except Exception as exc:
                results.errors.append(f"OSV query failed for {display_name}: {exc}")
                continue

            if response_data is None:
                continue

            for vuln in response_data.get("vulns", []):
                vuln_id = vuln.get("id", "")
                aliases = vuln.get("aliases", [])

                # Skip withdrawn vulns
                if vuln.get("withdrawn"):
                    continue

                # Check ignores against ID and all aliases
                all_ids = {vuln_id} | set(aliases)
                if all_ids & ignore_ids:
                    continue

                summary = vuln.get("summary", "") or vuln.get("details", "")
                fixed_versions = _extract_fixed_versions(vuln, display_name)

                results.vulnerabilities.append(
                    Vulnerability(
                        id=vuln_id,
                        aliases=aliases,
                        summary=summary,
                        fixed_versions=fixed_versions,
                        package=norm_name,
                        installed_version=version,
                    )
                )

    return results


def _query_package(display_name: str, version: str) -> dict[str, Any] | None:
    """Query OSV for a single package. Version is a top-level field."""
    payload = json.dumps({
        "version": version,
        "package": {"name": display_name, "ecosystem": "PyPI"},
    }).encode()
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == 0:
                continue
            raise

    return None


def _extract_fixed_versions(vuln: dict[str, Any], package_name: str) -> list[str]:
    """Extract fixed versions from an OSV vulnerability entry."""
    fixed: list[str] = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for r in affected.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            for event in r.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return sorted(fixed)
