"""Dependency graph building for uv.lock and pip/requirements-based projects."""

from __future__ import annotations

import importlib.metadata
import re
import tomllib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PackageInfo:
    name: str
    version: str
    dependencies: list[str] = field(default_factory=list)
    is_direct: bool = False


@dataclass
class DependencyGraph:
    """Resolved dependency graph with forward and reverse edges."""

    packages: dict[str, PackageInfo]  # normalized name -> PackageInfo
    reverse_map: dict[str, list[str]]  # package -> list of parents
    direct_deps: set[str]  # normalized names of direct dependencies

    def trace_chain(self, package: str) -> list[str]:
        """Find shortest path from a direct dependency to the given package.

        Returns a list like ["flask", "werkzeug", "markupsafe"] meaning
        flask -> werkzeug -> markupsafe.
        """
        package = normalize(package)
        if package in self.direct_deps:
            return [package]

        # BFS from package upward through reverse_map to find a direct dep
        visited: set[str] = {package}
        queue: deque[list[str]] = deque([[package]])

        while queue:
            path = queue.popleft()
            current = path[-1]

            for parent in self.reverse_map.get(current, []):
                if parent in visited:
                    continue
                visited.add(parent)
                new_path = path + [parent]
                if parent in self.direct_deps:
                    # Return in top-down order: direct dep -> ... -> target
                    new_path.reverse()
                    return new_path
                queue.append(new_path)

        # No path found to a direct dep — return just the package
        return [package]


def normalize(name: str) -> str:
    """Normalize a Python package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------
# uv mode
# ---------------------------------------------------------------------------


def parse_uv_lock(lock_path: Path | str) -> DependencyGraph:
    """Parse a uv.lock file and build the dependency graph."""
    lock_path = Path(lock_path)
    with lock_path.open("rb") as f:
        data = tomllib.load(f)

    packages: dict[str, PackageInfo] = {}
    root_names: set[str] = set()

    for pkg in data.get("package", []):
        name = normalize(pkg["name"])
        version = pkg.get("version", "0.0.0")

        # Identify root/workspace packages (virtual source or editable)
        source = pkg.get("source", {})
        is_root = isinstance(source, dict) and source.get("virtual") is not None
        is_editable = isinstance(source, dict) and source.get("editable") is not None
        if is_root or is_editable:
            root_names.add(name)

        # Collect runtime dependencies
        deps = [normalize(d["name"]) for d in pkg.get("dependencies", [])]

        packages[name] = PackageInfo(
            name=name,
            version=version,
            dependencies=deps,
        )

    # Direct deps are the runtime dependencies of root packages
    direct_deps: set[str] = set()
    for root in root_names:
        if root in packages:
            direct_deps.update(packages[root].dependencies)

    # Mark direct deps
    for dep_name in direct_deps:
        if dep_name in packages:
            packages[dep_name].is_direct = True

    # Build reverse map (who depends on whom)
    reverse_map: dict[str, list[str]] = {}
    for name, info in packages.items():
        for dep in info.dependencies:
            reverse_map.setdefault(dep, []).append(name)

    # Remove root packages from the scannable set — they're not real packages
    for root in root_names:
        packages.pop(root, None)

    return DependencyGraph(
        packages=packages,
        reverse_map=reverse_map,
        direct_deps=direct_deps,
    )


# ---------------------------------------------------------------------------
# pip mode
# ---------------------------------------------------------------------------

# Regex to extract package name from a Requires-Dist string
# e.g. "requests (>=2.0)" -> "requests"
# e.g. "foo[bar] >=1.0; extra == 'test'" -> "foo"
_REQUIRES_DIST_RE = re.compile(r"^([A-Za-z0-9][-A-Za-z0-9_.]*)")


def parse_pip_environment(
    requirements_path: Path | str | None = None,
) -> DependencyGraph:
    """Build dependency graph from installed packages in the current environment.

    If requirements_path is provided, packages listed there are marked as direct deps.
    Otherwise, packages that nothing depends on (top-level) are inferred as direct.
    """
    packages: dict[str, PackageInfo] = {}

    for dist in importlib.metadata.distributions():
        meta = dist.metadata
        name = normalize(meta["Name"])
        version = meta["Version"]

        # Parse Requires-Dist for dependencies
        deps: list[str] = []
        requires = dist.metadata.get_all("Requires-Dist") or []
        for req_str in requires:
            # Skip extras-only dependencies
            if "extra ==" in req_str:
                continue
            m = _REQUIRES_DIST_RE.match(req_str)
            if m:
                deps.append(normalize(m.group(1)))

        packages[name] = PackageInfo(name=name, version=version, dependencies=deps)

    # Determine direct dependencies
    direct_deps: set[str] = set()
    if requirements_path:
        direct_deps = _parse_requirements_txt(Path(requirements_path))
    else:
        # Infer: packages that nothing else depends on
        all_deps: set[str] = set()
        for info in packages.values():
            all_deps.update(info.dependencies)
        direct_deps = set(packages.keys()) - all_deps

    for dep_name in direct_deps:
        if dep_name in packages:
            packages[dep_name].is_direct = True

    # Build reverse map
    reverse_map: dict[str, list[str]] = {}
    for name, info in packages.items():
        for dep in info.dependencies:
            reverse_map.setdefault(dep, []).append(name)

    return DependencyGraph(
        packages=packages,
        reverse_map=reverse_map,
        direct_deps=direct_deps,
    )


def _parse_requirements_txt(path: Path) -> set[str]:
    """Extract package names from a requirements.txt file."""
    names: set[str] = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # "package==1.0" or "package>=1.0" or just "package"
        m = re.match(r"^([A-Za-z0-9][-A-Za-z0-9_.]*)", line)
        if m:
            names.add(normalize(m.group(1)))
    return names
