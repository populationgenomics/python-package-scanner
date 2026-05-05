"""Fetch per-edge dependency specifiers from PyPI metadata.

uv.lock stores the dependency graph but does not record each parent's version
specifier on a child package — only the root project's ``[package.metadata]``
block carries that information. To detect "blocked-upstream" findings (where
a transitive parent's upper-bound cap excludes the fix version) we have to
fetch ``requires_dist`` from PyPI for the parents of vulnerable packages.

This is best-effort: any fetch failure causes the parent's spec to be omitted
rather than raising, so a flaky network never makes the scanner fail.

Marker evaluation: a parent's ``requires_dist`` may list the same child several
times under different environment markers (e.g. one variant for
``python_version < "3.10"`` and another for ``python_version >= "3.10"``). Only
the variant whose marker matches the project's environment is relevant — if we
kept all variants we would surface phantom blockers. We evaluate markers using
``packaging.markers.Marker`` against an environment built from the project's
``requires-python`` and the running interpreter's other attributes.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from packaging.markers import Marker, default_environment

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


def build_marker_env(python_version: str | None = None) -> dict[str, str]:
    """Build a marker environment for evaluating ``requires_dist`` markers.

    Starts from ``packaging.markers.default_environment()`` (the running
    interpreter) and overrides ``python_version`` / ``python_full_version``
    when a project-level value is supplied.
    """
    env = dict(default_environment())
    if python_version:
        env["python_version"] = python_version
        env["python_full_version"] = f"{python_version}.0"
    return env


def filter_requires_dist(
    requires_dist: list[str], env: dict[str, str]
) -> dict[str, str]:
    """Resolve a parent's ``requires_dist`` list to a single spec per child.

    Drops entries whose marker excludes the given env (so multi-variant deps
    like urllib3-under-different-pythons collapse to the applicable one) and
    extras-only entries (rarely installed in the lockfile's runtime closure).
    """
    deps: dict[str, str] = {}
    for req_str in requires_dist:
        child, spec, marker = parse_requires_dist(req_str)
        if not child:
            continue
        if marker and "extra ==" in marker:
            continue
        if marker and not _marker_matches(marker, env):
            continue
        deps.setdefault(child, spec)
    return deps


def _marker_matches(marker_str: str, env: dict[str, str]) -> bool:
    """Return True if the marker is satisfied by ``env``.

    Conservative on parse/evaluate failure: returns True so we don't silently
    drop entries with unrecognised markers.
    """
    try:
        return Marker(marker_str).evaluate(environment=env)
    except Exception:
        return True


def fetch_constraints(
    parents: list[tuple[str, str]],
    env: dict[str, str] | None = None,
) -> ConstraintsMap:
    """Fetch ``requires_dist`` from PyPI for each (name, version) parent.

    Concurrent. Failures are silently dropped from the result. Inputs are
    deduplicated. ``env`` is the marker environment used to filter
    multi-variant deps; defaults to the running interpreter.
    """
    unique = list({p for p in parents if p[0] and p[1]})
    if not unique:
        return {}

    if env is None:
        env = build_marker_env()

    out: ConstraintsMap = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {
            ex.submit(_fetch_one, name, version, env): (name, version)
            for name, version in unique
        }
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                out[key] = fut.result()
            except Exception:
                continue
    return out


def _fetch_one(name: str, version: str, env: dict[str, str]) -> dict[str, str]:
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

    if data is None:
        return {}
    requires_dist = data.get("info", {}).get("requires_dist") or []
    return filter_requires_dist(requires_dist, env)
