"""Command line for Eslabon.

Usage: ``eslabon scan TARGET [--ecosystem {pypi,npm}] [--out PATH] [--offline]``.

Exit codes: 2 for any non-ok scan status or any user/IO error, 1 if the scan is
ok and produced findings, 0 otherwise. Errors print exactly one line on stderr,
never a traceback, and any attacker-influenced text is passed through clean_text.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from eslabon import osv, typosquat
from eslabon.catalog import load_catalog
from eslabon.emit import finding_event, summary_event, write_events
from eslabon.model import Anomaly, Limits, PackageRef, ScanResult
from eslabon.sanitize import clean_text
from eslabon.scan import analyze_archive, archive_kind, worst_status
from eslabon.worker import run_isolated

_CHUNK = 1 * 2**20
_ECOSYSTEMS = ("pypi", "npm")


class UsageError(Exception):
    """A user or IO error: reported as one stderr line and exit code 2."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # argparse would print usage + exit itself
        raise UsageError(message)


def _build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="eslabon", description="Static scanner for PyPI/npm archives."
    )
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    sc = sub.add_parser("scan", help="scan a local package archive")
    sc.add_argument("target", help="path to a local .whl, .tar.gz or .tgz archive")
    sc.add_argument("--ecosystem", choices=_ECOSYSTEMS)
    sc.add_argument("--out", type=Path, default=Path("events.jsonl"))
    sc.add_argument(
        "--offline",
        action="store_true",
        help="do not query OSV (osv_status is recorded as skipped)",
    )
    return parser


def exit_code(status: str, findings: int) -> int:
    if status != "ok":
        return 2
    return 1 if findings else 0


def _ecosystem(target: Path, requested: str | None) -> str:
    is_wheel = target.name.lower().endswith(".whl")
    if is_wheel and requested not in (None, "pypi"):
        raise UsageError("a .whl archive is always --ecosystem pypi")
    if is_wheel:
        return "pypi"
    if requested is None:
        raise UsageError("cannot infer the ecosystem; pass --ecosystem pypi or npm")
    return requested


def _sha256(path: Path, max_bytes: int) -> str:
    """Streaming SHA-256, refusing to read more than ``max_bytes``."""
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            total += len(chunk)
            if total > max_bytes:
                raise UsageError("archive changed size while it was being hashed")
            digest.update(chunk)
    return digest.hexdigest()


def _scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.is_file():
        raise UsageError(f"not a file: {clean_text(str(target), 512)}")
    ecosystem = _ecosystem(target, args.ecosystem)
    limits = Limits()
    scan_id = uuid.uuid4().hex
    try:
        size = os.stat(target).st_size
    except OSError as exc:
        raise UsageError(f"cannot stat target: {type(exc).__name__}") from exc

    if size > limits.max_download:
        # Refused before the archive is opened: no hash, no worker.
        result = ScanResult(
            status="limits_exceeded", findings=[], anomalies=[],
            error=f"archive larger than {limits.max_download}",
        )
        pkg = PackageRef(None, None, ecosystem, "")
    else:
        try:
            sha = _sha256(target, size)
        except OSError as exc:
            raise UsageError(f"cannot read target: {type(exc).__name__}") from exc
        request = PackageRef(None, None, ecosystem, sha)
        try:
            result = run_isolated(
                analyze_archive,
                (target, request, limits),
                timeout_s=limits.worker_timeout_s,
            )
        except Exception as exc:  # e.g. spawn/pickling failure: still summarise
            result = _failed(f"worker error: {type(exc).__name__}")
        pkg = PackageRef(result.metadata_name, result.metadata_version, ecosystem, sha)
    # Identity names first, on their own: a broken top list (ESL-005) must not
    # stop ESL-006, and vice versa. None means "could not be computed".
    idents: list[tuple[str, str | None]] | None
    try:
        idents = _identity_names(target, ecosystem, result)
    except Exception as exc:
        idents = None
        _downgrade(result, f"identity error: {type(exc).__name__}")
    try:
        for name, _ in idents or []:
            finding = typosquat.check(name, ecosystem)
            if finding is not None and finding not in result.findings:
                result.findings.append(finding)
    except Exception as exc:  # e.g. a missing or corrupt bundled top list
        _downgrade(result, f"typosquat error: {type(exc).__name__}")
    if args.offline:
        result.osv_status = "skipped"  # only ever the user's explicit opt-out
    else:
        _osv_checks(idents, ecosystem, result)

    now = datetime.now(UTC)
    # Findings first, then the summary, written separately: whatever goes wrong
    # with the findings, the summary is still attempted and reports it.
    try:
        catalog = load_catalog()
        findings = [
            finding_event(f, catalog[f.rule_id], pkg, scan_id, now)
            for f in result.findings
        ]
        if findings:
            write_events(findings, args.out)
    except Exception as exc:
        _downgrade(result, f"event error: {type(exc).__name__}")
    try:
        write_events([summary_event(result, pkg, scan_id, now)], args.out)
    except (OSError, ValueError) as exc:
        raise UsageError(f"cannot write events: {type(exc).__name__}") from exc
    return exit_code(result.status, len(result.findings))


_MISMATCH = "metadata name and archive file name differ"


def _identity_names(
    target: Path, ecosystem: str, result: ScanResult
) -> list[tuple[str, str | None]]:
    """The (name, version) pairs the package claims to be, for ESL-005/006.

    The name comes from the archive metadata; if there is none (no_metadata,
    ambiguous_metadata, or the worker never ran) it falls back to the name in
    the archive's FILE name, so an attacker cannot switch the rules off by
    breaking the metadata. If both exist and differ, both are returned and the
    anomaly identity_mismatch is recorded. Each name carries ITS OWN version:
    the metadata version for the metadata name (the file-name version if the
    metadata has none), the file-name version for the file-name name; None
    when no version is parseable for that name.
    """
    meta = result.metadata_name
    from_file = typosquat.identity_from_filename(
        target.name, archive_kind(target, ecosystem), meta
    )
    file_name, file_version = from_file if from_file else (None, None)
    idents: list[tuple[str, str | None]] = []
    if meta:
        result.identity_source = "metadata"
        same = file_name is not None and typosquat.same_identity(
            meta, file_name, ecosystem
        )
        version = result.metadata_version or (file_version if same else None)
        idents.append((meta, version))
        if file_name and not same:
            idents.append((file_name, file_version))
            result.anomalies.append(Anomaly("identity_mismatch", "", _MISMATCH))
    elif file_name:
        idents.append((file_name, file_version))
        result.identity_source = "filename"
    return idents


_NO_NAME = "osv: no package name to query"


def _osv_checks(
    idents: list[tuple[str, str | None]] | None, ecosystem: str, result: ScanResult
) -> None:
    """ESL-006: ask OSV about the names ESL-005 checks, each with its own
    version (even if the worker failed, so breaking the archive cannot switch
    the rule off).

    Fail closed: if there is no name to ask about (or the names could not be
    computed), OSV is "unavailable", not "skipped" -- "skipped" means only the
    user's --offline. An unavailable OSV makes the status at least
    osv_unavailable, never better than what the worker reported.
    """
    if not idents:
        osv_result = osv.OsvResult("unavailable", [], _NO_NAME)
    else:
        try:
            osv_result = osv.check(idents, ecosystem)
        except Exception as exc:  # osv.check fails closed itself; belt and braces
            error = f"osv error: {type(exc).__name__}"
            osv_result = osv.OsvResult("unavailable", [], error)
    result.osv_status = osv_result.status
    for finding in osv_result.findings:
        if finding not in result.findings:
            result.findings.append(finding)
    if osv_result.status == "unavailable":
        worse = worst_status(result.status, "osv_unavailable")
        if worse != result.status or result.error is None:
            result.error = osv_result.error
        result.status = worse


def _failed(error: str) -> ScanResult:
    return ScanResult(status="parse_error", findings=[], anomalies=[], error=error)


def _downgrade(result: ScanResult, error: str) -> None:
    """Mark ``result`` as failed (parse_error unless something worse already)."""
    worse = worst_status(result.status, "parse_error")
    if worse != result.status or result.error is None:
        result.error = error
    result.status = worse


def main(argv: list[str] | None = None) -> int:
    try:
        args = _build_parser().parse_args(argv)
        return _scan(args)
    except UsageError as exc:
        print(f"eslabon: error: {clean_text(str(exc), 512)}", file=sys.stderr)
        return 2
    except Exception as exc:  # last resort: one line, no traceback
        print(f"eslabon: error: internal error ({type(exc).__name__})", file=sys.stderr)
        return 2
