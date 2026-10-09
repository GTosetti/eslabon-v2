"""Package-name keys shared by fetch, cli and typosquat (PEP 503, npm scopes)."""

from __future__ import annotations

import re

_PEP503 = re.compile(r"[-_.]+")


def split_scope(name: str) -> tuple[str, str] | None:
    """(scope, bare) of an npm ``@scope/bare`` name, lowercased; else None."""
    if name.startswith("@") and "/" in name:
        scope, bare = name[1:].split("/", 1)
        return scope.lower(), bare.lower()
    return None


def registry_key(name: str, ecosystem: str) -> str:
    """Exemption key: the full name (scope kept), case-folded as the registry does."""
    if ecosystem == "npm":
        return name.lower()
    return _PEP503.sub("-", name).lower()


def normalize(name: str, ecosystem: str) -> str:
    """Comparison key: PEP 503 for PyPI; npm lowercased with ``@scope/`` stripped."""
    if ecosystem == "npm":
        scoped = split_scope(name)
        return scoped[1] if scoped else name.lower()
    return _PEP503.sub("-", name).lower()
