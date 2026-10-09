"""ESL-005: package-name typosquat check against bundled, dated top lists.

Package-level and pure: ``check`` looks at a name only, never at archive
content. It runs once per scan in the parent process (cli), after the worker
returned, on the name(s) the package claims to be.

Rule (docs/design.md section 5, controller ruling R43, variant "D+G"):

- The FULL name (npm scope kept) is exempt if it is in the top 5,000.
- Unscoped names: the normalised name (PEP 503 for PyPI, lowercase for npm) is
  compared with the normalised UNSCOPED top-1,000 names (a scoped target's bare
  name is never a target). Names shorter than 4 are not checked. Distance 1
  (Damerau-Levenshtein, optimal string alignment) fires from length 4.
  Distance 2 fires only from length 6, when the first characters match and the
  two edits are insertions, deletions or transpositions (no substitution).
  Trailing digits are NOT ignored: ``urllib33`` is a real squat.
- npm scoped names: skipped if the scope owns any top-5,000 name (nobody else
  can publish there). Otherwise reported only as scope confusion, when the bare
  name equals an unscoped top-1,000 name (``@evil/react`` vs ``react``).
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
MIN_LEN = 4  # shorter normalised names are not checked
D2_MIN_LEN = 6  # distance 2 needs at least this length
# npm's maximum name length. A longer name is never checked: it cannot be within
# distance 2 of any top-1,000 name anyway, so skipping it loses nothing.
MAX_NAME = 214
_ECOSYSTEMS = ("pypi", "npm")
_PEP503 = re.compile(r"[-_.]+")
_EVIDENCE_CAP = 512

# Tests replace this with small fixture lists ({ecosystem: TopList}).
_OVERRIDE: dict[str, TopList] = {}


def _split_scope(name: str) -> tuple[str, str] | None:
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
        scoped = _split_scope(name)
        return scoped[1] if scoped else name.lower()
    return _PEP503.sub("-", name).lower()


def threshold(normalized: str) -> int:
    """Largest distance that can fire for this normalised name (0: not checked)."""
    if len(normalized) < MIN_LEN:
        return 0
    return 2 if len(normalized) >= D2_MIN_LEN else 1


def _osa(a: str, b: str, sub_cost: int) -> int:
    """Optimal string alignment distance with the given substitution cost."""
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
            cost = 0 if ai == b[j - 1] else sub_cost
            best = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ai == b[j - 2] and a[i - 2] == b[j - 1]:
                best = min(best, prev2[j - 2] + 1)
            cur[j] = best
        prev2, prev = prev, cur
    return prev[-1]


def distance(a: str, b: str) -> int:
    """Damerau-Levenshtein distance, optimal string alignment variant.

    Insertions, deletions, substitutions and transpositions of two ADJACENT
    characters each cost 1; a substring is never edited twice (so
    ``distance("ca", "abc") == 3``). O(len(a) * len(b)); callers bound inputs.
    """
    return _osa(a, b, 1)


def _fires(key: str, target_key: str, limit: int) -> int | None:
    """The distance if ``key`` is a typo of ``target_key`` under the rule, else None."""
    d = distance(key, target_key)
    if d == 1:
        return d
    if (
        d == 2
        and limit >= 2
        and key[0] == target_key[0]
        and _osa(key, target_key, 2) <= 2  # the two edits use no substitution
    ):
        return d
    return None


@dataclass(frozen=True)
class TopList:
    """Exemption keys (top 5,000), comparison targets (UNSCOPED names among the
    top 1,000, in rank order) and, for npm, the scopes owning a top-5,000 name."""

    exempt: frozenset[str]
    targets: tuple[tuple[str, str], ...]  # (normalised key, name as listed)
    owned_scopes: frozenset[str] = frozenset()

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
        exempt = frozenset(registry_key(n, ecosystem) for n in names[:exempt_top])
        targets = tuple(
            (normalize(n, ecosystem), n)
            for n in names[:target_top]
            if ecosystem != "npm" or _split_scope(n) is None
        )
        owned: frozenset[str] = frozenset()
        if ecosystem == "npm":
            owned = frozenset(
                sc[0] for n in names[:exempt_top] if (sc := _split_scope(n))
            )
        return cls(exempt=exempt, targets=targets, owned_scopes=owned)


def bundled_top_document(ecosystem: str) -> dict:
    """The parsed bundled file src/eslabon/data/top_<eco>.json (all its keys)."""
    if ecosystem not in _ECOSYSTEMS:
        raise ValueError(f"unknown ecosystem: {ecosystem}")
    raw = files("eslabon").joinpath("data", f"top_{ecosystem}.json").read_bytes()
    return json.loads(raw)


@cache
def load_top_list(ecosystem: str) -> TopList:
    """The bundled list for ``ecosystem`` (src/eslabon/data/top_<eco>.json)."""
    names = bundled_top_document(ecosystem)["names"]
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
    if registry_key(name, ecosystem) in top.exempt:
        return None
    scoped = _split_scope(name) if ecosystem == "npm" else None
    if scoped is not None:
        return _scope_confusion(name, scoped, top)
    key = normalize(name, ecosystem)
    limit = threshold(key)
    if limit == 0:
        return None
    best: tuple[int, str] | None = None
    for target_key, target in top.targets:
        if abs(len(target_key) - len(key)) > limit:
            continue
        d = _fires(key, target_key, limit)
        if d is not None and (best is None or d < best[0]):
            best = (d, target)
            if d == 1:
                break  # nothing closer can fire: distance 0 is an exempt name
    if best is None:
        return None
    return _finding(name, best[1], f"distance {best[0]}")


def _scope_confusion(
    name: str, scoped: tuple[str, str], top: TopList
) -> Finding | None:
    scope, bare = scoped
    if not bare or scope in top.owned_scopes:
        return None  # an owned scope cannot be published to by an attacker
    for target_key, target in top.targets:
        if target_key == bare:
            return _finding(name, target, "scope confusion")
    return None


def _finding(name: str, target: str, why: str) -> Finding:
    shown = clean_text(name, _EVIDENCE_CAP)
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
_VERSION_CUT = re.compile(r"-(?=[0-9])")


def identity_from_filename(
    filename: str, kind: str, meta_name: str | None = None
) -> tuple[str, str | None] | None:
    """(name, version) claimed by an archive's FILE name, or None if no name.

    wheel: the first two ``-`` fields of ``{name}-{ver}-...whl``. sdist / npm:
    the archive suffix is stripped and the name ends at the LAST ``-`` followed
    by a digit (``evil-pkg-6.6.6.tar.gz`` -> ``evil-pkg``, ``6.6.6``); the
    version is everything after that ``-``. npm pack names a scoped package
    ``scope-name-ver.tgz``; that name is returned as given.

    With ``meta_name`` (the metadata name), a stem that starts with a spelling
    of that name followed by ``-<digit>`` gives that prefix first, so a rebuild
    suffix (``pyyaml-6.0-1.tar.gz`` -> ``pyyaml``, ``6.0-1``) is not a mismatch.
    The version is None when the file name has an empty one (``pkg-.whl``).
    Both values are attacker-controlled; callers clean them before display.
    """
    lower = filename.lower()
    if kind == "wheel":
        if not lower.endswith(".whl"):
            return None
        first, sep, rest = filename[: -len(".whl")].partition("-")
        if not (first and sep):
            return None
        return first, rest.split("-", 1)[0] or None
    for suffix in _ARCHIVE_SUFFIXES:
        if lower.endswith(suffix):
            stem = filename[: -len(suffix)]
            break
    else:
        return None
    if meta_name:
        eco = "npm" if kind == "npm" else "pypi"
        for cut in _VERSION_CUT.finditer(stem):
            prefix = stem[: cut.start()]
            if prefix and same_identity(meta_name, prefix, eco):
                return prefix, stem[cut.end():] or None
    m = _NAME_THEN_VERSION.match(stem)
    if not m:
        return None
    # greedy: the name is everything before the LAST "-<digit>"
    return m.group(1), stem[len(m.group(1)) + 1 :] or None


def name_from_filename(
    filename: str, kind: str, meta_name: str | None = None
) -> str | None:
    """The name part of identity_from_filename (see there)."""
    ident = identity_from_filename(filename, kind, meta_name)
    return ident[0] if ident else None


def same_identity(meta: str, from_file: str, ecosystem: str) -> bool:
    """True if the metadata name and the file name name the same package."""
    if ecosystem == "npm":
        f = from_file.lower()
        scoped = _split_scope(meta)
        if scoped:
            scope, bare = scoped
            return f in (bare, f"{scope}-{bare}")
        return f == meta.lower()
    return normalize(meta, ecosystem) == normalize(from_file, ecosystem)
