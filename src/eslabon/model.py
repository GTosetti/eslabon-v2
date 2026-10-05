"""Shared data model used by every Eslabon module."""

from __future__ import annotations

from dataclasses import dataclass
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
    path: str  # normalised
    data: bytes


# Anomaly kinds: traversal, absolute_path, link_skipped, zip_symlink, duplicate_name,
# encrypted_member, unsupported_compression, bad_member, weak_hash_sha1, no_metadata
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
    rules: yara.Rules
    limits: Limits
    pkg: PackageRef


@dataclass
class ScanResult:
    # ok|timeout|limits_exceeded|parse_error|hash_mismatch|fetch_error|osv_unavailable
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
