"""Minimal PEP 440 specifier evaluator (stdlib-only).

Handles the operators that appear in real-world ``Requires-Dist`` strings:
``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``, ``~=``.

Versions are compared on numeric release segments only. Pre-release/dev/local
suffixes are stripped — this is approximate but sufficient for upper-bound
cap detection (e.g. deciding whether ``3.13.4`` satisfies ``<4,>=3.11.16``).
Unrecognised clauses are ignored rather than raising, so a malformed PyPI
metadata entry never breaks classification.
"""

from __future__ import annotations

import re

_VERSION_RE = re.compile(r"^\s*v?(\d+(?:\.\d+)*)")
_OP_RE = re.compile(r"^\s*(==|!=|<=|>=|~=|<|>)\s*(.+?)\s*$")


def _parse(version: str) -> tuple[int, ...]:
    m = _VERSION_RE.match(version)
    if not m:
        return (0,)
    return tuple(int(x) for x in m.group(1).split("."))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def satisfies(version: str, spec: str) -> bool:
    """Return True if ``version`` satisfies the comma-separated ``spec``.

    An empty spec means anything is allowed.
    """
    if not spec or not spec.strip():
        return True
    v = _parse(version)
    for clause in spec.split(","):
        m = _OP_RE.match(clause)
        if not m:
            continue
        op, rhs = m.group(1), m.group(2)
        # Strip "==" wildcard suffix like "==1.4.*" by removing trailing ".*"
        rhs = rhs.rstrip().removesuffix(".*")
        rv = _parse(rhs)
        c = _cmp(v, rv)
        if op == "<" and not c < 0:
            return False
        if op == "<=" and not c <= 0:
            return False
        if op == ">" and not c > 0:
            return False
        if op == ">=" and not c >= 0:
            return False
        if op == "==" and not c == 0:
            return False
        if op == "!=" and not c != 0:
            return False
        if op == "~=":
            # ~= 1.4.2 means >= 1.4.2 and < 1.5
            if len(rv) < 2:
                continue
            if not c >= 0:
                return False
            cap = rv[:-1]
            cap = cap[:-1] + (cap[-1] + 1,)
            if _cmp(v, cap) >= 0:
                return False
    return True


def any_satisfies(versions: list[str], spec: str) -> bool:
    """Return True if at least one of ``versions`` satisfies ``spec``."""
    return any(satisfies(v, spec) for v in versions)
