"""Fetch per-edge dependency specifiers from PyPI metadata.

uv.lock stores the dependency graph but does not record each parent's version
specifier on a child package — only the root project's ``[package.metadata]``
block carries that information. To detect "blocked-upstream" findings (where
a transitive parent's upper-bound cap excludes the fix version) we have to
fetch ``requires_dist`` from PyPI for the parents of vulnerable packages.

This is best-effort: any fetch failure causes the parent's spec to be omitted
rather than raising, so a flaky network never makes the scanner fail.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from scanner.graph import normalize

PYPI_URL = "https://pypi.org/pypi/{name}/{version}/json"
TIMEOUT_SECONDS = 10
MAX_WORKERS = 10

# Matches the leading distribution name and an optional version specifier from
# a Requires-Dist string. Examples it must handle:
#   "aiohttp<4,>=3.11.16"
#   "azure-identity (>=1.6.0)"
#   "pillow ; extra == 'bokeh'"
#   "numpy>=1.20; python_version >= '3.10'"
_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9][-A-Za-z0-9_.]*)"  # name
    r"(?:\[[^\]]+\])?"  # optional extras
    r"\s*(?:\(([^)]*)\))?"  # parenthesised spec
    r"\s*([^;]*?)"  # bare spec (anything until ; or end)
    r"(?:\s*;\s*(.*))?\s*$"  # marker
)


def parse_requires_dist(req: str) -> tuple[str, str, str | None]:
    """Parse one Requires-Dist line into (name, specifier, marker).

    Returns empty name on failure. Specifier is "" if absent.
    """
    m = _REQ_RE.match(req)
    if not m:
        return ("", "", None)
    name = normalize(m.group(1))
    spec = (m.group(2) or m.group(3) or "").strip()
    marker = m.group(4)
    return (name, spec, marker)


# Type alias: maps (parent_name, parent_version) -> { child_name: specifier }
ConstraintsMap = dict[tuple[str, str], dict[str, str]]
ConstraintsProvider = Callable[[list[tuple[str, str]]], ConstraintsMap]


def fetch_constraints(parents: list[tuple[str, str]]) -> ConstraintsMap:
    """Fetch ``requires_dist`` from PyPI for each (name, version) parent.

    Concurrent. Failures are silently dropped from the result. Inputs are
    deduplicated.
    """
    unique = list({p for p in parents if p[0] and p[1]})
    if not unique:
        return {}

    out: ConstraintsMap = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {
            ex.submit(_fetch_one, name, version): (name, version)
            for name, version in unique
        }
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                out[key] = fut.result()
            except Exception:
                continue
    return out


def _fetch_one(name: str, version: str) -> dict[str, str]:
    url = PYPI_URL.format(name=name, version=version)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    data: dict | None = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
                data = json.loads(resp.read())
            break
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == 0:
                continue
            raise

    deps: dict[str, str] = {}
    if data is None:
        return deps
    for req_str in data.get("info", {}).get("requires_dist") or []:
        child, spec, marker = parse_requires_dist(req_str)
        if not child:
            continue
        # Skip extras-only deps like ``pillow ; extra == 'bokeh'`` — they only
        # apply when the parent is installed with that extra, which is rare in
        # the runtime closure that uv.lock represents.
        if marker and "extra ==" in marker:
            continue
        deps.setdefault(child, spec)
    return deps
