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
    # Per-child version specifier. Only populated for the root/workspace
    # packages, since uv.lock doesn't record specifiers for transitive deps.
    # Transitive specs are fetched from PyPI by scanner.constraints when
    # needed for blocked-upstream classification.
    dep_specs: dict[str, str] = field(default_factory=dict)
    is_direct: bool = False
    is_dev: bool = False


@dataclass
class DependencyGraph:
    """Resolved dependency graph with forward and reverse edges."""

    packages: dict[str, PackageInfo]  # normalized name -> PackageInfo
    reverse_map: dict[str, list[str]]  # package -> list of parents
    direct_deps: set[str]  # normalized names of direct runtime dependencies
    dev_deps: set[str] = field(default_factory=set)  # direct dev dependencies
    # Specifiers from the root project (typically pyproject.toml) on each direct
    # dep, e.g. {"hail": "~=0.2.137"}. Preserved separately so they survive the
    # removal of root packages from `packages`.
    root_specs: dict[str, str] = field(default_factory=dict)
    # Lower bound of the project's requires-python (e.g. "3.10"). Used as the
    # python_version for marker evaluation when filtering requires_dist
    # variants — picks the most permissive single value across the supported
    # range, so markers like `python_version < "3.10"` correctly drop out.
    python_version: str = ""

    def trace_chain(self, package: str) -> list[str]:
        """Find shortest path from a direct dependency to the given package.

        Searches runtime deps first, then dev deps. Returns a list like
        ["flask", "werkzeug", "markupsafe"] meaning flask -> werkzeug -> markupsafe.
        """
        package = normalize(package)
        all_direct = self.direct_deps | self.dev_deps

        if package in all_direct:
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
                if parent in all_direct:
                    new_path.reverse()
                    return new_path
                queue.append(new_path)

        # No path found to a direct dep — return just the package
        return [package]

    def is_dev_only(self, package: str) -> bool:
        """Check if a package is only reachable through dev dependencies."""
        package = normalize(package)
        if package in self.direct_deps:
            return False
        if package in self.dev_deps:
            return True

        chain = self.trace_chain(package)
        if not chain:
            return False
        root = chain[0]
        return root in self.dev_deps and root not in self.direct_deps


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

    python_version = _lower_bound_python_version(data.get("requires-python"))

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

        # For root/workspace packages, uv.lock embeds full requires-dist with
        # specifiers under [package.metadata]. Capture those so we can detect
        # caps in pyproject.toml without a PyPI fetch.
        dep_specs: dict[str, str] = {}
        if is_root or is_editable:
            metadata = pkg.get("metadata") or {}
            for entry in metadata.get("requires-dist") or []:
                child = normalize(entry.get("name", ""))
                spec = (entry.get("specifier") or "").strip()
                if child and spec:
                    dep_specs[child] = spec

        packages[name] = PackageInfo(
            name=name,
            version=version,
            dependencies=deps,
            dep_specs=dep_specs,
        )

    # Direct runtime deps from root packages
    direct_deps: set[str] = set()
    for root in root_names:
        if root in packages:
            direct_deps.update(packages[root].dependencies)

    # Dev deps from root packages
    dev_deps: set[str] = set()
    for pkg in data.get("package", []):
        name = normalize(pkg["name"])
        if name not in root_names:
            continue
        for _group, deps in pkg.get("dev-dependencies", {}).items():
            for d in deps:
                dev_deps.add(normalize(d["name"]))

    # Remove overlap — if a package is both runtime and dev, treat as runtime
    dev_deps -= direct_deps

    # Mark flags
    for dep_name in direct_deps:
        if dep_name in packages:
            packages[dep_name].is_direct = True
    for dep_name in dev_deps:
        if dep_name in packages:
            packages[dep_name].is_dev = True

    # Build reverse map (who depends on whom)
    reverse_map: dict[str, list[str]] = {}
    for name, info in packages.items():
        for dep in info.dependencies:
            reverse_map.setdefault(dep, []).append(name)

    # Capture root-level specifiers before we pop the root packages.
    root_specs: dict[str, str] = {}
    for root in root_names:
        info = packages.get(root)
        if info:
            root_specs.update(info.dep_specs)

    # Remove root packages from the scannable set — they're not real packages.
    # Root names are intentionally preserved as parents in reverse_map so that
    # trace_chain() and build_findings() can recognise direct deps via their
    # parent chain.
    for root in root_names:
        packages.pop(root, None)

    return DependencyGraph(
        packages=packages,
        reverse_map=reverse_map,
        direct_deps=direct_deps,
        dev_deps=dev_deps,
        root_specs=root_specs,
        python_version=python_version,
    )


_REQUIRES_PYTHON_RE = re.compile(r"(?:>=|~=)\s*(\d+\.\d+)")


def _lower_bound_python_version(requires_python: str | None) -> str:
    """Extract the lower bound major.minor from a PEP 440 requires-python string.

    e.g. ">=3.10,<3.12" -> "3.10". Returns "" if absent or unparseable.
    """
    if not requires_python:
        return ""
    m = _REQUIRES_PYTHON_RE.search(requires_python)
    return m.group(1) if m else ""


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

    # Local import to avoid a hard cycle with constraints which imports normalize.
    from scanner.constraints import parse_requires_dist

    for dist in importlib.metadata.distributions():
        meta = dist.metadata
        name = normalize(meta["Name"])
        version = meta["Version"]

        deps: list[str] = []
        dep_specs: dict[str, str] = {}
        requires = dist.metadata.get_all("Requires-Dist") or []
        for req_str in requires:
            child, spec, marker = parse_requires_dist(req_str)
            if not child:
                continue
            if marker and "extra ==" in marker:
                continue
            deps.append(child)
            if spec:
                dep_specs.setdefault(child, spec)

        packages[name] = PackageInfo(
            name=name,
            version=version,
            dependencies=deps,
            dep_specs=dep_specs,
        )

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

    import sys

    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"

    return DependencyGraph(
        packages=packages,
        reverse_map=reverse_map,
        direct_deps=direct_deps,
        python_version=python_version,
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
