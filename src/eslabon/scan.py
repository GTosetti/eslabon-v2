"""Scan orchestration: one streaming pass over an archive, inside the worker.

``analyze_archive`` is module-level so ``worker.run_isolated`` can run it in a
spawned child. It reads every member exactly once and, in that same pass, runs
the analysers and picks up the package metadata (name/version). Nothing is
extracted to disk and no package code is ever imported or executed.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Callable
from pathlib import Path

from eslabon.archive import TarStats, iter_members, normalize_path
from eslabon.model import (
    Anomaly,
    Finding,
    Limits,
    LimitsExceeded,
    Member,
    PackageRef,
    ParseError,
    ScanContext,
    ScanResult,
)

# Worst first. When several statuses apply, the earliest one in this list wins.
STATUS_PRECEDENCE = (
    "timeout",
    "limits_exceeded",
    "parse_error",
    "hash_mismatch",
    "fetch_error",
    "incomplete",
    "osv_unavailable",
    "ok",
)
# Anomaly kinds meaning "content exists that was not scanned".
INCOMPLETE_KINDS = frozenset(
    {"encrypted_member", "unsupported_compression", "bad_member"}
)

# Analysers run on every member. Filled from Task 9 onwards.
ANALYZERS: list[Callable[[Member, ScanContext], list[Finding]]] = []

_META_HEADER_CAP = 64 * 2**10  # RFC 822 headers live at the top; never scan more
_SDIST_PKG_INFO = re.compile(r"[^/]+/PKG-INFO")
_WHEEL_METADATA = re.compile(r"[^/]+\.dist-info/METADATA")
_LINE_BREAK = re.compile(r"\r\n|\r|\n")
_NO_METADATA = "no package metadata found"
_AMBIGUOUS = "several candidate metadata files or .dist-info dirs"

_rules_cache: object | None = None


def worst_status(*statuses: str) -> str:
    """The highest-precedence status among ``statuses`` (unknown ones rank worst)."""
    rank = {s: i for i, s in enumerate(STATUS_PRECEDENCE)}
    return min(statuses, key=lambda s: rank.get(s, -1), default="ok")


def _get_rules() -> object | None:
    """Compile the rule set once per worker process. Task 9 provides the rules."""
    return _rules_cache


def _is_metadata_path(path: str, ecosystem: str) -> bool:
    if ecosystem == "npm":
        return path == "package.json"  # archive.normalize_path drops the top dir
    return bool(_SDIST_PKG_INFO.fullmatch(path) or _WHEEL_METADATA.fullmatch(path))


def _parse_rfc822(data: bytes) -> tuple[str, str] | None:
    """Name/Version from the header block of PKG-INFO / METADATA (first wins)."""
    text = data[:_META_HEADER_CAP].decode("utf-8", errors="replace")
    found: dict[str, str] = {}
    for line in _LINE_BREAK.split(text):
        if line == "":
            break  # end of headers; the description body follows
        if line[0] in " \t":
            continue  # continuation of a previous header
        key, sep, value = line.partition(":")
        if not sep:
            break  # not a header: the block is malformed, stop here
        key = key.strip().lower()
        if key in ("name", "version") and key not in found:
            found[key] = value.strip()
    name, version = found.get("name"), found.get("version")
    if name and version:
        return name, version
    return None


def _parse_package_json(data: bytes) -> tuple[str, str] | None:
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    name, version = doc.get("name"), doc.get("version")
    if isinstance(name, str) and isinstance(version, str) and name and version:
        return name, version
    return None


def parse_metadata(m: Member, ecosystem: str) -> tuple[str, str] | None:
    """(name, version) if ``m`` is the package's metadata file and it parses.

    sdist: ``<top dir>/PKG-INFO``; wheel: ``<name>.dist-info/METADATA`` (both RFC
    822 headers); npm: the normalised top-level ``package.json``. The values are
    attacker-controlled; emit cleans them. Anything malformed returns None.
    """
    if not _is_metadata_path(m.path, ecosystem):
        return None
    if ecosystem == "npm":
        return _parse_package_json(m.data)
    return _parse_rfc822(m.data)


def _rewritten(raw: str, ecosystem: str) -> bool:
    """True if the landing place of ``raw`` is uncertain.

    That is: normalisation had to rewrite it (traversal, absolute, drive), or it
    contains a backslash (a separator on Windows, a literal character on POSIX)
    or a NUL (some tools cut the name there).
    Such members are never metadata candidates.
    """
    if chr(0x5C) in raw or chr(0) in raw:  # NUL: truncated by some readers
        return True
    return bool(normalize_path(raw, ecosystem)[1])


class _MetadataPicker:
    """Choose the metadata file by archive kind; refuse to guess between several.

    wheel (zip, pypi): only ``<x>.dist-info/METADATA``, with exactly one
    ``.dist-info`` dir in the archive. sdist (tar, pypi): only
    ``<single top dir>/PKG-INFO``. npm: only a ``package.json`` whose raw path
    has exactly two components (a bare ``package.json`` is dropped by strip:1).
    A rewritten or backslash member is never a candidate; if it WOULD be one
    under any reading (backslash as '/', '..' resolved or dropped), the result
    is ambiguous, since some installer could let it win.
    """

    def __init__(self, ecosystem: str) -> None:
        self.ecosystem = ecosystem
        self.mode = ""  # decided on the first member, once the container is known
        self.candidates: list[tuple[str, str] | None] = []
        self.dirs: set[str] = set()
        self.suspect = False

    def _wanted(self, parts: list[str]) -> bool:
        if len(parts) != 2:
            return False
        if self.mode == "wheel":
            return parts[0].endswith(".dist-info") and parts[1] == "METADATA"
        if self.mode == "sdist":
            return parts[1] == "PKG-INFO"
        return parts[1] == "package.json"

    def see(self, m: Member, raw: str, rewritten: bool, archive_kind: str) -> None:
        if not self.mode:
            if self.ecosystem == "npm":
                self.mode = "npm"
            else:
                self.mode = "wheel" if archive_kind == "zip" else "sdist"
        if rewritten:
            as_slash = raw.replace(chr(0x5C), "/")
            readings = (
                posixpath.normpath(as_slash).lstrip("/").split("/"),
                normalize_path(raw, "pypi")[0].split("/"),  # '..' dropped, no strip
            )
            if any(self._wanted(r) for r in readings):
                self.suspect = True
            return
        parts = posixpath.normpath(raw).split("/")
        if self.mode == "wheel" and parts[0].endswith(".dist-info"):
            self.dirs.add(parts[0])
        if self.mode == "sdist":
            self.dirs.add(parts[0])
        if self._wanted(parts):
            self.candidates.append(parse_metadata(m, self.ecosystem))

    def result(self) -> tuple[str, str] | None | str:
        """(name, version), None (nothing usable) or "ambiguous"."""
        if self.suspect or len(self.candidates) > 1:
            return "ambiguous"
        if self.mode == "wheel" and len(self.dirs) > 1:
            return "ambiguous"
        if self.mode == "sdist" and self.candidates and len(self.dirs) > 1:
            return "ambiguous"
        return self.candidates[0] if self.candidates else None


def analyze_archive(path: Path, pkg: PackageRef, limits: Limits) -> ScanResult:
    """Read every member once, run ANALYZERS and collect metadata.

    Every copy of a duplicated name is scanned and all its findings are kept;
    which copy an installer leaves on disk cannot be emulated reliably across
    installers and OSes. Duplicates are flagged by the ``duplicate_name`` anomaly.
    """
    eco = pkg.ecosystem
    ctx = ScanContext(rules=_get_rules(), limits=limits, pkg=pkg)
    anomalies: list[Anomaly] = []
    findings: list[Finding] = []
    stats = TarStats()
    picker = _MetadataPicker(eco)
    status, error = "ok", None
    try:
        for m in iter_members(path, eco, limits, anomalies, stats=stats):
            raw = m.raw_path or m.path
            picker.see(m, raw, _rewritten(raw, eco), stats.kind)
            for analyze in ANALYZERS:
                findings.extend(analyze(m, ctx))
    except LimitsExceeded as exc:
        status, error = "limits_exceeded", str(exc)
    except ParseError as exc:
        status, error = "parse_error", str(exc)

    if any(a.kind in INCOMPLETE_KINDS for a in anomalies):
        status = worst_status(status, "incomplete")
    meta = picker.result()
    if meta == "ambiguous":
        anomalies.append(Anomaly("ambiguous_metadata", "", _AMBIGUOUS))
        meta = None
    elif meta is None and status == "ok":
        anomalies.append(Anomaly(kind="no_metadata", path_hex="", detail=_NO_METADATA))
    return ScanResult(
        status=status,
        findings=findings,
        anomalies=anomalies,
        files_scanned=stats.files_scanned,
        bytes_read=stats.bytes_read,
        error=error,
        metadata_name=meta[0] if meta else None,
        metadata_version=meta[1] if meta else None,
    )
