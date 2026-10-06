"""Shared data model used by every Eslabon module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import yara


@dataclass(frozen=True)
class Limits:
    max_download: int = 50 * 2**20
    max_total: int = 200 * 2**20
    max_file: int = 10 * 2**20
    max_members: int = 5000
    max_zip_cd: int = 5000 * (46 + 512)
    worker_timeout_s: float = 120.0
    yara_timeout_s: int = 10


@dataclass(frozen=True)
class Member:
    index: int  # order in archive
    # normalised, lossy: '..' dropped, drive stripped, backslash -> '/'. Use raw_path
    # to know where an installer really writes the member.
    path: str
    data: bytes
    raw_path: str = ""  # member name exactly as stored in the archive


# Anomaly kinds: traversal, absolute_path, link_skipped, zip_symlink, duplicate_name,
# encrypted_member, unsupported_compression, bad_member, unknown_type, weak_hash_sha1,
# no_metadata, ambiguous_metadata, special_member (tar fifo/chr/blk: no content),
# overlapped_entry (zip entries sharing a local header; still scanned),
# dir_with_content (zip entry that looks like a directory but carries data or whose
# stored and host-mapped names disagree; read and scanned as a regular member),
# bad_package_json (a root npm package.json with a JSON syntax error or a non-object
# root; npm refuses it, so ESL-002 records nothing for it; invalid UTF-8 is NOT
# this: npm decodes with U+FFFD and so do we),
# package_json_too_deep (a root package.json nested too deep for Python's json,
# which V8's iterative parser reads fine: its scripts went unchecked).
# Only encrypted_member, unsupported_compression, bad_member and
# package_json_too_deep mean "content not scanned" and make the status "incomplete".
@dataclass(frozen=True)
class Anomaly:
    kind: str
    path_hex: str
    detail: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    file: str
    member_index: int  # -1 for package-level rules
    line: int
    snippet: str
    match_count: int
    name_hex: str


@dataclass(frozen=True)
class PackageRef:
    name: str | None
    version: str | None
    ecosystem: str
    archive_sha256: str


@dataclass(frozen=True)
class ScanContext:
    rules: yara.Rules | None  # None until the rule set exists (Task 9)
    limits: Limits
    pkg: PackageRef
    # "sdist" | "wheel" | "npm"; "" when unknown (rules scoped to a kind stay off)
    archive_kind: str = ""
    # Analysers append member-level anomalies here (e.g. bad_package_json);
    # scan.analyze_archive passes its own list.
    anomalies: list[Anomaly] = field(default_factory=list)


@dataclass
class ScanResult:
    # ok|timeout|limits_exceeded|parse_error|hash_mismatch|fetch_error|incomplete|
    # osv_unavailable (precedence: scan.STATUS_PRECEDENCE)
    status: str
    findings: list[Finding]
    anomalies: list[Anomaly]
    files_scanned: int = 0
    bytes_read: int = 0
    osv_status: str = "skipped"  # ok|unavailable|skipped
    duration_ms: int = 0
    error: str | None = None
    metadata_name: str | None = None
    metadata_version: str | None = None


class LimitsExceeded(Exception):
    pass


class ParseError(Exception):
    pass


class FetchError(Exception):
    pass


class HashMismatch(Exception):
    pass
