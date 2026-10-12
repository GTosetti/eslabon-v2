"""Public text carries no private planning codes.

The project was planned with short internal labels (a letter and a digit for
stages, milestones and review rounds, numbered work items). They mean nothing
to a reader of the public repository, so every file git tracks (or would track:
untracked files that are not ignored) is checked for them.

The patterns are assembled from pieces so this file does not match itself.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent

_D = "[0-9]"
# A capital letter and a digit standing alone as a word: stage, milestone,
# review round, minor finding and fix labels.
_CODE = re.compile(
    r"\b(?:"
    + "|".join(
        (
            "H[0-8]",
            "E[0-8]",
            "R[1-9]" + _D + "?",
            "M[1-6]",
            "F" + _D + "{1,2}",
        )
    )
    + r")\b"
)
# Numbered work items and stage references.
_WORK_ITEM = re.compile(r"(?i)\b" + "ta" + "sk ?" + _D + r"+[a-z]?\b")
_STAGE = re.compile(r"(?i)\b" + "sta" + "ge e" + _D)
PATTERNS = (_CODE, _WORK_ITEM, _STAGE)

# Text that legitimately looks like a code and is stripped before matching.
_NOT_CODES = (
    # Linter suppressions name rule codes, e.g. a ruff line-length rule.
    # Only the code list is stripped, so a comment after it is still checked.
    re.compile(r"#\s*noqa:?\s*[A-Z]+[0-9]+(?:\s*,\s*[A-Z]+[0-9]+)*"),
    # Long hex runs (SHA-256 digests, scan ids) can contain a letter-digit pair.
    re.compile(r"\b[0-9a-fA-F]{16,}\b"),
)

# Raw lab evidence is kept byte-identical to what the lab printed (snapshot
# descriptions, probe rule descriptions, third-party Wazuh rule names). It is
# a record, not prose, so it is not rewritten; its README is prose and checked.
_RAW_EVIDENCE = "docs/evidence/lab/"
_RAW_EVIDENCE_PROSE = {"docs/evidence/lab/README.md"}
# Bundled registry name lists: package names are third-party data.
_DATA_JSON = re.compile(r"src/eslabon/data/[^/]+\.json")
# The ruff configuration lists rule codes by design (a selector such as a
# letter and one digit is a valid rule group): quoted codes are stripped there,
# its comments are still checked.
_RULE_CODE_FILES = {"pyproject.toml"}
_QUOTED_RULE_CODE = re.compile(r'"[A-Z]{1,4}[0-9]{0,4}"')


def _listed_files() -> list[str]:
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not available")
    try:
        inside = subprocess.run(  # noqa: S603 -- fixed argv, no shell
            [git, "rev-parse", "--is-inside-work-tree"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        pytest.skip("git could not be started")
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        pytest.skip("not a git work tree")
    out = subprocess.run(  # noqa: S603 -- fixed argv, no shell
        [git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout
    return sorted({p for p in out.decode("utf-8").split("\0") if p})


def _excluded(rel: str) -> bool:
    if rel.startswith(_RAW_EVIDENCE) and rel not in _RAW_EVIDENCE_PROSE:
        return True
    return bool(_DATA_JSON.fullmatch(rel))


def _text(path: Path) -> str | None:
    """The file as text, or None when it is missing (deleted in the work tree,
    renamed by a parallel edit) or binary."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def find_codes(text: str) -> list[tuple[int, str]]:
    """(line number, matched token) for every internal code in text."""
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        for cleaner in _NOT_CODES:
            line = cleaner.sub("", line)
        for pattern in PATTERNS:
            hits.extend((number, m.group(0)) for m in pattern.finditer(line))
    return hits


def test_public_files_carry_no_internal_codes():
    hits = []
    for rel in _listed_files():
        if _excluded(rel):
            continue
        text = _text(ROOT / rel)
        if text is None:
            continue
        if rel in _RULE_CODE_FILES:
            text = _QUOTED_RULE_CODE.sub('""', text)
        hits.extend(f"{rel}:{n}: {token}" for n, token in find_codes(text))
    assert hits == [], "internal codes in public files:\n" + "\n".join(hits)


@pytest.mark.parametrize(
    "line",
    [
        "Closed in " + "E" + "7.",
        "see " + "R" + "59 for the reason",
        "fixes " + "M" + "1 and " + "M" + "2",
        "After " + "Ta" + "sk 16 the wheel",
        "from " + "ta" + "sk 4b",
        "the " + "Sta" + "ge E" + "3 notes",
        "milestone " + "H" + "5",
        "item " + "F" + "11",
        "z = 3  # noqa: S310 -- see " + "R" + "62",
    ],
)
def test_detector_catches_codes(line):
    assert find_codes(line)


@pytest.mark.parametrize(
    "line",
    [
        "x = 1  # noqa: " + "E" + "501",
        "y = 2  # noqa: " + "E" + "7, S310 -- shape check",
        "sha256 0f" + "e7" * 20 + "ab",
        "ESL-001 maps to T1059.006 and ATT&CK v19.2",
        "an E2E test, the H2O module, a 2FA prompt",
        "SHA256 and R2D2",
        "Hexlify 1E7 bytes",
    ],
)
def test_detector_ignores_lookalikes(line):
    assert find_codes(line) == []
