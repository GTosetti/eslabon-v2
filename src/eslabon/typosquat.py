"""ESL-005: package-name typosquat check against bundled, dated top lists.

Package-level and pure: ``check`` looks at a name only, never at archive
content. It runs once per scan in the parent process (cli), after the worker
returned, on the name(s) the package claims to be.

Rule (docs/design.md section 5): the FULL name (npm scope kept) is exempt if it
is in the top 5,000 of its ecosystem. Otherwise its normalised form (PEP 503 for
PyPI; lowercase with any ``@scope/`` stripped for npm) is compared with the
normalised top 1,000 using Damerau-Levenshtein distance (optimal string
alignment). Threshold: 1 if the normalised name has 5 characters or fewer,
else 2. Distance 0 can only happen across a scope (``@evil/react`` vs
``react``) and is reported as scope confusion.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import cache
from importlib.resources import files

from eslabon.model import Finding
from eslabon.sanitize import clean_text, to_hex

RULE_ID = "ESL-005"
EXEMPT_TOP = 5000
TARGET_TOP = 1000
# npm's maximum name length. A longer name is never checked: it cannot be within
# distance 2 of any top-1,000 name anyway, so skipping it loses nothing.
MAX_NAME = 214
_ECOSYSTEMS = ("pypi", "npm")
_PEP503 = re.compile(r"[-_.]+")
_EVIDENCE_CAP = 512

# Tests replace this with small fixture lists ({ecosystem: TopList}).
_OVERRIDE: dict[str, TopList] = {}


def _strip_scope(name: str) -> str:
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[1]
    return name


def normalize(name: str, ecosystem: str) -> str:
    """Comparison key: PEP 503 for PyPI; npm lowercased with ``@scope/`` stripped."""
    if ecosystem == "npm":
        return _strip_scope(name).lower()
    return _PEP503.sub("-", name).lower()


def _full_key(name: str, ecosystem: str) -> str:
    """Exemption key: the full name (scope kept), case-folded as the registry does."""
    if ecosystem == "npm":
        return name.lower()
    return _PEP503.sub("-", name).lower()


def threshold(normalized: str) -> int:
    return 1 if len(normalized) <= 5 else 2


def distance(a: str, b: str) -> int:
    """Damerau-Levenshtein distance, optimal string alignment variant.

    Insertions, deletions, substitutions and transpositions of two ADJACENT
    characters each cost 1; a substring is never edited twice (so
    ``distance("ca", "abc") == 3``). O(len(a) * len(b)); callers bound inputs.
    """
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        ai = a[i - 1]
        for j in range(1, len(b) + 1):
            cost = 0 if ai == b[j - 1] else 1
            best = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ai == b[j - 2] and a[i - 2] == b[j - 1]:
                best = min(best, prev2[j - 2] + 1)
            cur[j] = best
        prev2, prev = prev, cur
    return prev[-1]


@dataclass(frozen=True)
class TopList:
    """Exemption keys (top 5,000) and comparison targets (top 1,000, in rank order)."""

    exempt: frozenset[str]
    targets: tuple[tuple[str, str], ...]  # (normalised key, name as listed)

    @classmethod
    def from_names(
        cls,
        names: list[str],
        ecosystem: str,
        exempt_top: int = EXEMPT_TOP,
        target_top: int = TARGET_TOP,
    ) -> TopList:
        if ecosystem not in _ECOSYSTEMS:
            raise ValueError(f"unknown ecosystem: {ecosystem}")
        exempt = frozenset(_full_key(n, ecosystem) for n in names[:exempt_top])
        targets = tuple((normalize(n, ecosystem), n) for n in names[:target_top])
        return cls(exempt=exempt, targets=targets)


@cache
def load_top_list(ecosystem: str) -> TopList:
    """The bundled list for ``ecosystem`` (src/eslabon/data/top_<eco>.json)."""
    if ecosystem not in _ECOSYSTEMS:
        raise ValueError(f"unknown ecosystem: {ecosystem}")
    raw = files("eslabon").joinpath("data", f"top_{ecosystem}.json").read_bytes()
    names = json.loads(raw)["names"]
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise ValueError(f"malformed top list for {ecosystem}")
    return TopList.from_names(names, ecosystem)


def active_top_list(ecosystem: str) -> TopList:
    if ecosystem in _OVERRIDE:
        return _OVERRIDE[ecosystem]
    return load_top_list(ecosystem)


def check(name: str, ecosystem: str, top: TopList | None = None) -> Finding | None:
    """ESL-005 finding for ``name``, or None. Pure: depends on the name only."""
    if top is None:
        top = active_top_list(ecosystem)
    if not name or len(name) > MAX_NAME:
        return None
    if _full_key(name, ecosystem) in top.exempt:
        return None
    key = normalize(name, ecosystem)
    if not key:
        return None
    limit = threshold(key)
    best: tuple[int, str] | None = None
    for target_key, target in top.targets:
        if abs(len(target_key) - len(key)) > limit:
            continue
        d = distance(key, target_key)
        if d <= limit and (best is None or d < best[0]):
            best = (d, target)
            if d == 0:
                break
    if best is None:
        return None
    d, target = best
    shown = clean_text(name, _EVIDENCE_CAP)
    why = "scope confusion" if d == 0 else f"distance {d}"
    return Finding(
        rule_id=RULE_ID,
        file=shown,
        member_index=-1,
        line=0,
        snippet=f"{shown} ~ {target} ({why})",
        match_count=1,
        name_hex=to_hex(name),
    )


# ------------------------------------------------------------ identity ----

_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".zip")
_NAME_THEN_VERSION = re.compile(r"(.+)-[0-9]", re.DOTALL)


def name_from_filename(filename: str, kind: str) -> str | None:
    """Package name claimed by an archive's FILE name, or None.

    wheel: the first ``-`` field of ``{name}-{ver}-...whl``. sdist / npm: the
    archive suffix is stripped and the name ends at the LAST ``-`` followed by a
    digit (``evil-pkg-6.6.6.tar.gz`` -> ``evil-pkg``). npm pack names a scoped
    package ``scope-name-ver.tgz``; that is returned as given.
    """
    lower = filename.lower()
    if kind == "wheel":
        if not lower.endswith(".whl"):
            return None
        first, sep, _ = filename[: -len(".whl")].partition("-")
        return first if first and sep else None
    for suffix in _ARCHIVE_SUFFIXES:
        if lower.endswith(suffix):
            stem = filename[: -len(suffix)]
            break
    else:
        return None
    m = _NAME_THEN_VERSION.match(stem)
    if not m:
        return None
    return m.group(1)  # greedy: everything before the LAST "-<digit>"


def same_identity(meta: str, from_file: str, ecosystem: str) -> bool:
    """True if the metadata name and the file name name the same package."""
    if ecosystem == "npm":
        f = from_file.lower()
        full = meta.lower()
        if full.startswith("@") and "/" in full:
            scope, bare = full[1:].split("/", 1)
            return f in (bare, f"{scope}-{bare}")
        return f == full
    return normalize(meta, ecosystem) == normalize(from_file, ecosystem)
