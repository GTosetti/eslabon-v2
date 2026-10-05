"""Scan orchestration: one streaming pass over an archive, inside the worker.

``analyze_archive`` is module-level so ``worker.run_isolated`` can run it in a
spawned child. It reads every member exactly once and, in that same pass, runs
the analysers and picks up the package metadata (name/version). Nothing is
extracted to disk and no package code is ever imported or executed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

from eslabon.archive import TarStats, iter_members
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


def analyze_archive(path: Path, pkg: PackageRef, limits: Limits) -> ScanResult:
    """Read every member once, run ANALYZERS and collect metadata.

    Duplicate normalised paths follow last-copy-wins (that is the copy an
    installer leaves on disk): findings from earlier copies are dropped.
    """
    ctx = ScanContext(rules=_get_rules(), limits=limits, pkg=pkg)
    anomalies: list[Anomaly] = []
    findings: list[Finding] = []
    stats = TarStats()
    index_path: dict[int, str] = {}
    last_index: dict[str, int] = {}
    meta: tuple[str, str] | None = None
    status, error = "ok", None
    try:
        for m in iter_members(path, pkg.ecosystem, limits, anomalies, stats=stats):
            index_path[m.index] = m.path
            last_index[m.path] = m.index
            if _is_metadata_path(m.path, pkg.ecosystem):
                meta = parse_metadata(m, pkg.ecosystem)  # last copy wins here too
            for analyze in ANALYZERS:
                findings.extend(analyze(m, ctx))
    except LimitsExceeded as exc:
        status, error = "limits_exceeded", str(exc)
    except ParseError as exc:
        status, error = "parse_error", str(exc)

    def is_last_copy(f: Finding) -> bool:
        if f.member_index < 0:  # package-level finding
            return True
        return last_index.get(index_path.get(f.member_index, "")) == f.member_index

    findings = [f for f in findings if is_last_copy(f)]
    if meta is None:
        anomalies.append(Anomaly(kind="no_metadata", path_hex="", detail=_NO_METADATA))
    if any(a.kind in INCOMPLETE_KINDS for a in anomalies):
        status = worst_status(status, "incomplete")
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
