"""ESL-005 typosquat: normalisation, distance, check() and the bundled top lists.

No test touches the network. Mechanics use small injected TopList fixtures; the
exemption tests also run against the bundled data files, which are part of the
package (src/eslabon/data).
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from importlib.resources import files

import pytest

from eslabon import typosquat
from eslabon.names import normalize
from eslabon.sanitize import to_hex
from eslabon.typosquat import (
    TopList,
    check,
    distance,
    identity_from_filename,
    name_from_filename,
)

PYPI = TopList.from_names(
    [
        "boto3", "requests", "numpy", "numba", "boto", "typing-extensions", "six",
        "urllib3", "beautifulsoup4", "abcdefgh", "abcdefg",
    ],
    "pypi",
)
NPM = TopList.from_names(
    [
        "react", "ms", "qs", "ws", "chalk", "chai", "@babel/core", "lodash",
        "@types/node", "eslint", "typescript",
    ],
    "npm",
)


def _bundled(ecosystem: str) -> TopList:
    return typosquat.load_top_list(ecosystem)


# ------------------------------------------------------------- brief ----


def test_reqeusts_flagged_against_requests():
    f = check("reqeusts", "pypi", PYPI)
    assert f is not None
    assert f.rule_id == "ESL-005"
    assert f.file == "reqeusts"
    assert f.member_index == -1 and f.line == 0 and f.match_count == 1
    assert f.snippet == "reqeusts ~ requests (distance 1)"
    assert f.name_hex == to_hex("reqeusts")


def test_reqeusts_flagged_with_bundled_list():
    f = check("reqeusts", "pypi", _bundled("pypi"))
    assert f is not None and f.snippet == "reqeusts ~ requests (distance 1)"


TOP_NAMES = [
    ("ms", "npm"), ("qs", "npm"), ("ws", "npm"), ("chalk", "npm"), ("chai", "npm"),
    ("numpy", "pypi"), ("numba", "pypi"), ("boto", "pypi"), ("boto3", "pypi"),
    ("@babel/core", "npm"),
]


@pytest.mark.parametrize(("name", "eco"), TOP_NAMES)
def test_top_names_never_flagged(name, eco):
    fixture = PYPI if eco == "pypi" else NPM
    assert check(name, eco, fixture) is None
    assert check(name, eco, _bundled(eco)) is None


def test_scope_confusion_evil_react():
    f = check("@evil/react", "npm", NPM)
    assert f is not None
    assert f.snippet == "@evil/react ~ react (scope confusion)"
    assert f.file == "@evil/react"


def test_pep503_normalisation():
    assert normalize("Typing_Extensions", "pypi") == "typing-extensions"
    assert normalize("typing.extensions", "pypi") == "typing-extensions"
    assert normalize("A__b-._C", "pypi") == "a-b-c"
    # an exempt name stays exempt under any PEP 503 spelling
    assert check("Typing_Extensions", "pypi", PYPI) is None


def test_npm_normalisation_strips_scope_and_lowercases():
    assert normalize("@Babel/Core", "npm") == "core"
    assert normalize("JSONStream", "npm") == "jsonstream"
    assert normalize("left-pad", "npm") == "left-pad"


def test_short_name_threshold_is_1():
    # length 4-5: only distance 1 counts
    assert check("numpi", "pypi", PYPI) is not None  # distance 1 from numpy
    assert check("nampi", "pypi", PYPI) is None  # distance 2: too far for a short name
    assert check("abcde", "pypi", PYPI) is None  # 2 deletions, but only 5 long
    # longer names: distance 2 counts (no substitution), 3 does not
    f = check("requsts", "pypi", PYPI)
    assert f is not None and f.snippet.endswith("(distance 1)")
    assert check("rxqxxsts", "pypi", PYPI) is None  # distance 3


def test_names_shorter_than_4_are_not_checked():
    assert check("siz", "pypi", PYPI) is None  # distance 1 from six, but length 3
    assert check("sixx", "pypi", PYPI) is not None  # length 4: checked
    assert check("rect", "npm", NPM) is not None  # length 4, distance 1 from react
    assert check("rea", "npm", NPM) is None


def test_distance_2_needs_no_substitution_and_same_first_char():
    # two deletions, same first character, length >= 6: fires
    f = check("abcdef", "pypi", PYPI)  # vs abcdefgh (and abcdefg at distance 1)
    assert f is not None and f.snippet == "abcdef ~ abcdefg (distance 1)"
    f = check("requts", "pypi", PYPI)  # 2 deletions from requests
    assert f is not None and f.snippet == "requts ~ requests (distance 2)"
    f = check("reqeustss", "pypi", PYPI)  # transposition + insertion
    assert f is not None and f.snippet.endswith("(distance 2)")
    # two substitutions: OSA distance 2, but not a typo shape
    assert distance("rexuezts", "requests") == 2
    assert check("rexuezts", "pypi", PYPI) is None
    # one substitution + one deletion is also refused at distance 2
    assert check("rexuests", "pypi", PYPI) is not None  # distance 1: allowed
    assert check("rexusts", "pypi", PYPI) is None
    # first character differs: distance 2 refused
    assert check("equestss", "pypi", PYPI) is None


def test_digit_squats_fire():
    assert check("urllib33", "pypi", PYPI) is not None
    assert check("beautifulsoup44", "pypi", PYPI) is not None
    assert check("chalk2", "npm", NPM) is not None
    assert check("typescript3", "npm", NPM) is not None


def test_distance_transposition_is_1():
    assert distance("requests", "reqeusts") == 1
    assert distance("ab", "ba") == 1


@pytest.mark.parametrize(
    ("a", "b", "d"),
    [
        ("", "", 0), ("", "abc", 3), ("abc", "", 3), ("kitten", "sitting", 3),
        ("abc", "abc", 0), ("abcd", "acbd", 1), ("ca", "abc", 3),  # OSA, not true DL
        ("abc", "abd", 1), ("abc", "abcd", 1),
    ],
)
def test_distance_values(a, b, d):
    assert distance(a, b) == d
    assert distance(b, a) == d


# -------------------------------------------------------- list mechanics ----


def _far_apart_names(n: int) -> list[str]:
    # random-looking 12-hex names are ~10 edits apart from each other
    return [hashlib.sha256(str(i).encode()).hexdigest()[:12] for i in range(n)]


def _one_edit(name: str) -> str:
    return name[:-1] + ("g" if name[-1] != "g" else "h")


def test_exemption_covers_top_5000_but_targets_only_top_1000():
    names = _far_apart_names(6000)
    names[5500] = _one_edit(names[10])  # beyond the top 5,000: not exempt
    names[3000] = _one_edit(names[20])  # inside the top 5,000: exempt
    top = TopList.from_names(names, "pypi")
    assert len(top.targets) == 1000 and len(top.exempt) == 5000
    assert check(names[3000], "pypi", top) is None
    f = check(names[5500], "pypi", top)
    assert f is not None and f.snippet == f"{names[5500]} ~ {names[10]} (distance 1)"
    # rank 4000 is in the exemption list but is not a target
    assert check(_one_edit(names[4000]), "pypi", top) is None
    assert check(_one_edit(names[999]), "pypi", top) is not None


def test_scoped_target_is_never_a_comparison_target():
    # "@evil/core" vs "@babel/core": the target is scoped, so no comparison
    assert check("@evil/core", "npm", NPM) is None
    # unscoped names are never compared with a scoped target's bare name
    assert check("node", "npm", NPM) is None
    assert check("nodee", "npm", NPM) is None
    assert check("core", "npm", NPM) is None


def test_owned_scope_is_skipped():
    # @types and @babel own top-5,000 names: nobody else can publish there
    assert check("@types/node", "npm", NPM) is None
    assert check("@types/nodee", "npm", NPM) is None
    assert check("@babel/cor", "npm", NPM) is None
    # the bare name is a target, but the scope is owned
    assert check("@babel/react", "npm", NPM) is None
    assert check("@Babel/react", "npm", NPM) is None  # scopes are case-insensitive


def test_unowned_scope_confusion():
    f = check("@typescript_eslinter/eslint", "npm", NPM)
    assert f is not None
    assert f.snippet == "@typescript_eslinter/eslint ~ eslint (scope confusion)"
    # an unowned scope with a bare name that is only NEAR a target: not reported
    assert check("@evil/reakt", "npm", NPM) is None
    assert check("@evil/my-tool", "npm", NPM) is None


def test_closest_target_wins_and_one_finding():
    top = TopList.from_names(["abcdefgh", "abcdefgx"], "pypi")
    f = check("abcdefgz", "pypi", top)
    assert f is not None and f.snippet == "abcdefgz ~ abcdefgh (distance 1)"


def test_overlong_or_empty_name_is_skipped():
    assert check("r" * 215, "pypi", PYPI) is None
    assert check("", "pypi", PYPI) is None
    assert check("@scope/", "npm", NPM) is None


def test_unrelated_name_not_flagged():
    assert check("my-private-tool", "pypi", PYPI) is None
    assert check("left-pad", "npm", NPM) is None


def test_finding_file_is_cleaned():
    f = check("reqeusts\x1b", "pypi", PYPI)
    assert f is not None and "\x1b" not in f.file and "\x1b" not in f.snippet
    assert f.name_hex == to_hex("reqeusts\x1b")


def test_check_one_name_against_1000_targets_is_fast():
    top = _bundled("pypi")
    start = time.perf_counter()
    for name in ("reqeusts", "nmupy", "this-is-a-much-longer-name", "x"):
        check(name, "pypi", top)
    assert (time.perf_counter() - start) / 4 < 0.05


# --------------------------------------------------------- bundled data ----


@pytest.mark.parametrize("eco", ["pypi", "npm"])
def test_bundled_list_shape(eco):
    raw = files("eslabon").joinpath("data", f"top_{eco}.json").read_bytes()
    doc = json.loads(raw)
    assert set(doc) == {"source", "retrieved", "names"}
    assert doc["source"].startswith("https://")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", doc["retrieved"])
    names = doc["names"]
    assert len(names) == 6000 and len(set(names)) == 6000
    assert all(isinstance(n, str) and 0 < len(n) <= 214 for n in names)
    top = _bundled(eco)
    assert len(top.exempt) <= 5000
    assert len(top.targets) == 1000 if eco == "pypi" else 0 < len(top.targets) <= 1000


def test_load_top_list_rejects_unknown_ecosystem():
    with pytest.raises(ValueError):
        typosquat.load_top_list("cargo")


# ------------------------------------------------------ filename identity ----


@pytest.mark.parametrize(
    ("filename", "kind", "expected"),
    [
        ("requests-2.32.3-py3-none-any.whl", "wheel", "requests"),
        ("typing_extensions-4.12.2-py3-none-any.whl", "wheel", "typing_extensions"),
        ("reqeusts-1.0.tar.gz", "sdist", "reqeusts"),
        ("evil-pkg-6.6.6.tar.gz", "sdist", "evil-pkg"),
        ("Django-4.2.tar.bz2", "sdist", "Django"),
        ("legacy-pkg-1.0.zip", "sdist", "legacy-pkg"),
        ("pkg-1.0.tgz", "sdist", "pkg"),
        ("left-pad-1.3.0.tgz", "npm", "left-pad"),
        ("babel-core-7.0.0.tgz", "npm", "babel-core"),
        ("clean.tgz", "npm", None),
        ("anon.tar.gz", "sdist", None),
        ("-1.0.tgz", "npm", None),
        ("noversion.whl", "wheel", None),
        ("x.unknown", "sdist", None),
    ],
)
def test_name_from_filename(filename, kind, expected):
    assert name_from_filename(filename, kind) == expected


@pytest.mark.parametrize(
    ("filename", "kind", "meta", "expected"),
    [
        ("foo-1.0.0-2.tgz", "npm", "foo", "foo"),
        ("foo-1.0.0-2.tgz", "npm", None, "foo-1.0.0"),  # no metadata: last "-<digit>"
        ("pyyaml-6.0-1.tar.gz", "sdist", "PyYAML", "pyyaml"),
        ("pyyaml-6.0-1.tar.gz", "sdist", None, "pyyaml-6.0"),
        ("Typing_Ext-1.0-1.tar.gz", "sdist", "typing.ext", "Typing_Ext"),
        ("evil-react-1.0.0-1.tgz", "npm", "@evil/react", "evil-react"),
        ("other-1.0-1.tar.gz", "sdist", "pyyaml", "other-1.0"),  # no prefix match
        ("pyyaml2-6.0.tar.gz", "sdist", "pyyaml", "pyyaml2"),  # prefix needs "-<digit>"
    ],
)
def test_name_from_filename_prefers_the_metadata_name(filename, kind, meta, expected):
    assert name_from_filename(filename, kind, meta) == expected


@pytest.mark.parametrize(
    ("filename", "kind", "meta", "expected"),
    [
        ("requests-2.32.3-py3-none-any.whl", "wheel", None, ("requests", "2.32.3")),
        ("pkg-.whl", "wheel", None, ("pkg", None)),
        ("chalk-5.6.2.tgz", "npm", None, ("chalk", "5.6.2")),
        ("chalk-5.6.2-beta.1.tgz", "npm", None, ("chalk", "5.6.2-beta.1")),
        ("evil-pkg-6.6.6.tar.gz", "sdist", None, ("evil-pkg", "6.6.6")),
        ("pyyaml-6.0-1.tar.gz", "sdist", "PyYAML", ("pyyaml", "6.0-1")),
        ("foo-1.0.0-2.tgz", "npm", None, ("foo-1.0.0", "2")),
        ("noversion.whl", "wheel", None, None),
        ("clean.tgz", "npm", None, None),
        ("payload.tar.gz", "sdist", None, None),
    ],
)
def test_identity_from_filename_name_and_version(filename, kind, meta, expected):
    assert identity_from_filename(filename, kind, meta) == expected
    name = expected[0] if expected else None
    assert name_from_filename(filename, kind, meta) == name
