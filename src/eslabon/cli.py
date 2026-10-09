"""Command line for Eslabon.

Usage: ``eslabon scan TARGET [--ecosystem {pypi,npm}] [--out PATH] [--offline]``.

TARGET is a local archive or ``name==version``; the latter (``--ecosystem``
required) is resolved on the registry and downloaded by fetch.py over HTTPS into
a temporary directory outside the working tree, scanned like a local file, and
deleted. Nothing is ever installed or executed.

Exit codes: 2 for any non-ok scan status or any user/IO error, 1 if the scan is
ok and produced findings, 0 otherwise. Errors print exactly one line on stderr,
never a traceback, and any attacker-influenced text is passed through clean_text.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import sys
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from eslabon import fetch, osv, typosquat
from eslabon.catalog import load_catalog
from eslabon.emit import finding_event, summary_event, write_events
from eslabon.model import (
    Anomaly,
    FetchError,
    HashMismatch,
    Limits,
    LimitsExceeded,
    PackageRef,
    ScanResult,
)
from eslabon.sanitize import clean_text
from eslabon.scan import analyze_archive, archive_kind, worst_status
from eslabon.worker import run_isolated

_CHUNK = 1 * 2**20
_ECOSYSTEMS = ("pypi", "npm")
# name==version; fullmatch, so a trailing newline does not slip through "$"
_TARGET = re.compile(r"^(@[a-z0-9._-]+/)?[A-Za-z0-9._-]+==[A-Za-z0-9.+!_-]+$")


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
    sc = sub.add_parser("scan", help="scan a package archive")
    sc.add_argument(
        "target",
        help="a local .whl/.tar.gz/.tgz archive, or name==version (needs --ecosystem)",
    )
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


def _parse_argument(text: str, ecosystem: str | None) -> tuple[str, str, str]:
    """(name, version, ecosystem) of a ``name==version`` target, or UsageError."""
    if not _TARGET.fullmatch(text):
        raise UsageError(f"not a file or name==version: {clean_text(text, 512)}")
    if ecosystem is None:
        raise UsageError("name==version needs --ecosystem pypi or npm")
    name, version = text.split("==", 1)
    if name.startswith("@") and ecosystem != "npm":
        raise UsageError("a scoped @scope/name is an npm package")
    bare = name.rsplit("/", 1)[-1]
    if not (fetch.has_alnum(bare) and fetch.has_alnum(version)):
        raise UsageError("name and version need a letter or digit")
    return name, version, ecosystem


def _scan_file(target: Path, ecosystem: str, limits: Limits) -> tuple[ScanResult, str]:
    """Hash and analyse an archive file: (result, its sha256, "" if not hashed)."""
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
        return result, ""
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
    return result, sha


def _scan_registry(
    name: str, version: str, ecosystem: str, limits: Limits
) -> tuple[ScanResult, str]:
    """Fetch name==version and scan it: (result, sha256 of what we got or "").

    The archive is the only package data ever written to disk: one file, under
    its sanitised registry file name (so its suffix decides the archive kind as
    for a local file), in a fresh tempfile.mkdtemp() directory, removed with that
    directory whatever happens. It is never extracted, installed or executed.
    If the temp dir lands inside the cwd or the repo, nothing is fetched
    (fetch_error). A dir rmtree could not remove is reported on stderr and as
    the anomaly temp_leftover (not "incomplete").
    """
    tmp = Path(tempfile.mkdtemp(prefix="eslabon-"))
    try:
        if _temp_dir_unsafe(tmp):
            # TMPDIR/TEMP/TMP point into the working tree or the repo (or
            # mkdtemp fell back to the cwd): hostile bytes must not land there
            result, sha = _fetch_failed("fetch_error", _TEMP_UNSAFE, None), ""
        else:
            result, sha = _fetch_and_scan(name, version, ecosystem, limits, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if os.path.lexists(tmp):
        # one stderr line; not "incomplete": the scan itself is complete
        where = clean_text(str(tmp), 512)
        print(f"eslabon: warning: temp dir not removed: {where}", file=sys.stderr)
        result.anomalies.append(Anomaly("temp_leftover", "", where))
    return result, sha


_TEMP_UNSAFE = "temp dir inside working tree"


def _protected_roots() -> list[Path]:
    """The cwd and the Eslabon source tree (repo root when run from src/)."""
    package = Path(__file__).resolve().parent
    roots = [Path.cwd().resolve(), package]
    if package.parent.name == "src":
        roots.append(package.parent.parent)
    return roots


def _temp_dir_unsafe(tmp: Path) -> bool:
    """True if ``tmp`` is inside the cwd or the repo, or that cannot be told.

    Two checks. Textual: the resolved path under a resolved root (covers case
    and 8.3 spellings). By file identity: every existing entry of ``tmp`` and
    its parents is compared with each root by (st_dev, st_ino), because
    resolve() keeps ``\\\\?\\C:\\...`` and UNC (``\\\\localhost\\C$\\...``)
    spellings whose text never matches the root's. Any OSError fails closed.
    """
    try:
        real = tmp.resolve()
        roots = _protected_roots()
        if any(real == root or root in real.parents for root in roots):
            return True
        root_ids = {_file_id(root) for root in roots}
        for entry in (real, *real.parents):
            if os.path.lexists(entry) and _file_id(entry) in root_ids:
                return True
    except OSError:
        return True
    return False


def _file_id(path: Path) -> tuple[int, int]:
    st = os.stat(path)
    if st.st_ino == 0:  # no file identity on this file system: cannot tell
        raise OSError("no file id")
    return st.st_dev, st.st_ino


def _fetch_and_scan(
    name: str, version: str, ecosystem: str, limits: Limits, tmp: Path
) -> tuple[ScanResult, str]:
    artifact: fetch.Artifact | None = None
    deadline = fetch.new_deadline()
    try:
        artifact = fetch.resolve(name, version, ecosystem, deadline=deadline)
        path, anomalies = fetch.download(artifact, tmp, limits, deadline=deadline)
    except HashMismatch as exc:
        failed = _fetch_failed("hash_mismatch", str(exc), artifact)
        return failed, exc.actual_sha256
    except LimitsExceeded as exc:
        return _fetch_failed("limits_exceeded", str(exc), artifact), ""
    except FetchError as exc:
        return _fetch_failed("fetch_error", str(exc), artifact), ""
    except Exception as exc:  # fail closed on anything unexpected
        error = f"fetch error: {type(exc).__name__}"
        return _fetch_failed("fetch_error", error, artifact), ""
    result, sha = _scan_file(path, ecosystem, limits)
    result.anomalies.extend(anomalies)
    return result, sha


def _fetch_failed(
    status: str, error: str, artifact: fetch.Artifact | None
) -> ScanResult:
    anomalies = fetch.hash_anomalies(artifact) if artifact else []
    return ScanResult(status=status, findings=[], anomalies=anomalies, error=error)


def _scan(args: argparse.Namespace) -> int:
    limits = Limits()
    scan_id = uuid.uuid4().hex
    target = Path(args.target)
    argument: tuple[str, str] | None = None
    if target.is_file():
        ecosystem = _ecosystem(target, args.ecosystem)
        result, sha = _scan_file(target, ecosystem, limits)
        pkg = PackageRef(result.metadata_name, result.metadata_version, ecosystem, sha)
    else:
        name, version, ecosystem = _parse_argument(args.target, args.ecosystem)
        argument = (name, version)
        result, sha = _scan_registry(name, version, ecosystem, limits)
        # the requested name and version are the identity; ESL-005/006 still
        # run on them when the fetch or the worker failed (R42/R46)
        pkg = PackageRef(name, version, ecosystem, sha)
    # Identity names first, on their own: a broken top list (ESL-005) must not
    # stop ESL-006, and vice versa. None means "could not be computed".
    idents: list[tuple[str, str | None]] | None
    try:
        idents = _identity_names(target, ecosystem, result, argument)
    except Exception as exc:
        idents = None
        _downgrade(result, f"identity error: {type(exc).__name__}")
    if idents == []:
        # R47: ESL-005/006 cannot run without a name -- the scan is incomplete,
        # with or without --offline
        result.anomalies.append(Anomaly("no_identity", "", _NO_IDENTITY))
        _downgrade(result, _NO_IDENTITY, to="incomplete")
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
_ARG_MISMATCH = "metadata name and requested name differ"
_NO_IDENTITY = "no package name from metadata or file name"


def _same_requested(meta: str, requested: str, ecosystem: str) -> bool:
    """Same registry name (npm: case-folded, scope kept; PyPI: PEP 503)."""
    if ecosystem == "npm":
        return meta.lower() == requested.lower()
    key = typosquat.registry_key
    return key(meta, "pypi") == key(requested, "pypi")


def _argument_identity(
    argument: tuple[str, str], ecosystem: str, result: ScanResult
) -> list[tuple[str, str | None]]:
    """name==version targets: the requested name/version first, then the
    metadata's if it names another package (identity_mismatch) or the same
    package with another version (R47: OSV is asked about both)."""
    name, version = argument
    result.identity_source = "argument"
    idents: list[tuple[str, str | None]] = [(name, version)]
    meta, meta_version = result.metadata_name, result.metadata_version
    if meta and not _same_requested(meta, name, ecosystem):
        idents.append((meta, meta_version))
        result.anomalies.append(Anomaly("identity_mismatch", "", _ARG_MISMATCH))
    elif meta and meta_version and meta_version != version:
        idents.append((name, meta_version))
    return idents


def _identity_names(
    target: Path,
    ecosystem: str,
    result: ScanResult,
    argument: tuple[str, str] | None = None,
) -> list[tuple[str, str | None]]:
    """The (name, version) pairs the package claims to be, for ESL-005/006.

    The name comes from the archive metadata; if there is none (no_metadata,
    ambiguous_metadata, or the worker never ran) it falls back to the name in
    the archive's FILE name, so an attacker cannot switch the rules off by
    breaking the metadata. If both exist and differ, both are returned and the
    anomaly identity_mismatch is recorded. Each name carries ITS OWN version:
    the metadata version for the metadata name (the file-name version if the
    metadata has none), the file-name version for the file-name name; None
    when no version is parseable for that name. If metadata and file name name
    the same package with different versions, the name is returned once per
    version (R47), so OSV is asked about both.

    For a ``name==version`` target, see _argument_identity.
    """
    if argument is not None:
        return _argument_identity(argument, ecosystem, result)
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
        if same and file_version and file_version != version:
            idents.append((meta, file_version))
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
        _downgrade(result, osv_result.error, to="osv_unavailable")


def _failed(error: str) -> ScanResult:
    return ScanResult(status="parse_error", findings=[], anomalies=[], error=error)


def _downgrade(result: ScanResult, error: str, to: str = "parse_error") -> None:
    """Degrade ``result`` to status ``to`` unless it is already worse; ``error``
    is kept only if the status got worse or no error was recorded yet."""
    worse = worst_status(result.status, to)
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
