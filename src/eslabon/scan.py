"""Scan orchestration: one streaming pass over an archive, inside the worker.

``analyze_archive`` is module-level so ``worker.run_isolated`` can run it in a
spawned child. It reads every member exactly once and, in that same pass, runs
the analysers and picks up the package metadata (name/version). Nothing is
extracted to disk and no package code is ever imported or executed.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from pathlib import Path

from eslabon import npm_scripts, yara_engine
from eslabon.archive import TarStats, is_rewritten, iter_members, path_readings
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
    {
        "encrypted_member",
        "unsupported_compression",
        "bad_member",
        npm_scripts.PACKAGE_JSON_TOO_DEEP,
        "no_identity",  # added by the cli: ESL-005/006 had no name to check
    }
)

# Analysers run on every member. Registered here, at import time, because the
# spawned worker re-imports this module and never sees runtime registration.
ANALYZERS: list[Callable[[Member, ScanContext], list[Finding]]] = [
    yara_engine.scan_member,
    npm_scripts.scan_package_json,
]

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
    """Compile the rule set once per process (module-level cache)."""
    global _rules_cache
    if _rules_cache is None:
        _rules_cache = yara_engine.compile_rules()
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
    return _name_version(npm_scripts.load_package_json(data)[0])


def _name_version(doc: dict | None) -> tuple[str, str] | None:
    """name/version of a package.json read by npm_scripts.load_package_json."""
    if doc is None:
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


class _MetadataPicker:
    """Choose the metadata file by archive kind; refuse to guess between several.

    wheel (a .whl file, pypi): only ``<x>.dist-info/METADATA``, with exactly one
    ``.dist-info`` dir in the archive. sdist (any other pypi archive): only
    ``<single top dir>/PKG-INFO``. npm: only a ``package.json`` whose raw path
    has exactly two components (a bare ``package.json`` is dropped by strip:1).
    A rewritten or backslash member is never a candidate; if it WOULD be one
    under any reading (backslash as '/', '..' resolved or dropped), the result
    is ambiguous, since some installer could let it win.
    """

    def __init__(self, ecosystem: str, kind: str) -> None:
        self.ecosystem = ecosystem
        # "wheel" / "sdist" / "npm": from the suffix, as ESL-001 reads it
        self.mode = kind
        self.candidates: list[tuple[str, str] | None] = []
        self.dirs: set[str] = set()
        self.suspect = False
        # package.json candidates Python could not read but npm can (too deep)
        self.problems: list[Anomaly] = []

    def _wanted(self, parts: list[str]) -> bool:
        if len(parts) != 2:
            return False
        if self.mode == "wheel":
            return parts[0].endswith(".dist-info") and parts[1] == "METADATA"
        if self.mode == "sdist":
            return parts[1] == "PKG-INFO"
        return parts[1] == "package.json"

    def see(self, m: Member, raw: str, rewritten: bool) -> None:
        if rewritten:
            if any(self._wanted(r.split("/")) for r in path_readings(raw)):
                self.suspect = True
            return
        parts = posixpath.normpath(raw).split("/")
        if self.mode == "wheel" and parts[0].endswith(".dist-info"):
            self.dirs.add(parts[0])
        if self.mode == "sdist":
            self.dirs.add(parts[0])
        if not self._wanted(parts):
            return
        if self.mode != "npm":
            self.candidates.append(parse_metadata(m, self.ecosystem))
            return
        doc, problem = npm_scripts.load_package_json(m.data)
        if problem == npm_scripts.PACKAGE_JSON_TOO_DEEP:
            self.problems.append(npm_scripts.package_json_anomaly(problem, raw))
        self.candidates.append(_name_version(doc))

    def result(self) -> tuple[str, str] | None | str:
        """(name, version), None (nothing usable) or "ambiguous"."""
        if self.suspect or len(self.candidates) > 1:
            return "ambiguous"
        if self.mode == "wheel" and len(self.dirs) > 1:
            return "ambiguous"
        if self.mode == "sdist" and self.candidates and len(self.dirs) > 1:
            return "ambiguous"
        return self.candidates[0] if self.candidates else None


def archive_kind(path: Path, ecosystem: str) -> str:
    """"npm", "wheel" (a .whl file) or "sdist" (any other PyPI archive,
    legacy .zip sdists included)."""
    if ecosystem == "npm":
        return "npm"
    return "wheel" if path.suffix.lower() == ".whl" else "sdist"


def analyze_archive(path: Path, pkg: PackageRef, limits: Limits) -> ScanResult:
    """Read every member once, run ANALYZERS and collect metadata.

    Every copy of a duplicated name is scanned and all its findings are kept;
    which copy an installer leaves on disk cannot be emulated reliably across
    installers and OSes. Duplicates are flagged by the ``duplicate_name`` anomaly.
    """
    eco = pkg.ecosystem
    anomalies: list[Anomaly] = []
    ctx = ScanContext(
        rules=_get_rules(),
        limits=limits,
        pkg=pkg,
        archive_kind=archive_kind(path, eco),
        anomalies=anomalies,
    )
    findings: list[Finding] = []
    stats = TarStats()
    picker = _MetadataPicker(eco, ctx.archive_kind)
    status, error = "ok", None
    try:
        for m in iter_members(path, eco, limits, anomalies, stats=stats):
            raw = m.stored_path
            picker.see(m, raw, is_rewritten(raw, eco))
            for analyze in ANALYZERS:
                findings.extend(analyze(m, ctx))
    except LimitsExceeded as exc:
        status, error = "limits_exceeded", str(exc)
    except ParseError as exc:
        status, error = "parse_error", str(exc)

    for problem in picker.problems:
        if problem not in anomalies:  # ESL-002 may have recorded it already
            anomalies.append(problem)
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
