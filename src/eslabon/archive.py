"""Streaming, capped readers for hostile package archives.

Nothing in this module writes to disk or follows links. Every decompressed byte
passes through _CountingReader, which enforces Limits.max_total on what is
actually produced, not on what the headers declare.
"""

from __future__ import annotations

import bz2
import re
import tarfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from eslabon.model import Anomaly, Limits, LimitsExceeded, Member, ParseError
from eslabon.sanitize import to_hex

_CHUNK = 64 * 2**10
MAX_META = 1 * 2**20  # per pax/GNU-long header and per chain; global pax cumulative
_PATH_HEX_MAX = 1024
_GZ_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZh"
_ZIP_MAGIC = b"PK\x03\x04"
_DRIVE = re.compile(r"^[A-Za-z]:")


@dataclass
class TarStats:
    """Counters filled in while iterating (ScanResult.bytes_read / files_scanned)."""

    bytes_read: int = 0
    files_scanned: int = 0


def normalize_path(raw: str, ecosystem: str) -> tuple[str, list[str]]:
    """Return (safe relative path, anomaly kinds) for an archive member name."""
    kinds: list[str] = []
    p = raw.replace("\\", "/")
    if p.startswith("/"):
        kinds.append("absolute_path")
    elif _DRIVE.match(p):
        kinds.append("absolute_path")
        p = p[2:]
    parts = [s for s in p.split("/") if s not in ("", ".")]
    if ".." in parts:
        kinds.append("traversal")
        parts = [s for s in parts if s != ".."]
    if ecosystem == "npm" and len(parts) > 1:
        parts = parts[1:]
    return ("/".join(parts) or "_", kinds)


class _CountingReader:
    """File-like .read(n) over a raw file, optionally decompressing gzip/bz2.

    Decompression is bounded by max_length, so a bomb never expands more than
    n bytes per call. Raises LimitsExceeded once the total produced exceeds
    limits.max_total, ParseError on corrupt or trailing non-zero data.
    """

    def __init__(self, raw: BinaryIO, kind: str, limits: Limits) -> None:
        self._raw = raw
        self._kind = kind  # "gz" | "bz2" | "tar"
        self._limits = limits
        self._in = b""
        self._done = False
        self._d = self._new_decompressor() if kind != "tar" else None
        self.total = 0

    def _new_decompressor(self):
        if self._kind == "gz":
            return zlib.decompressobj(wbits=31)
        return bz2.BZ2Decompressor()

    def _raw_read(self) -> bytes:
        return self._raw.read(_CHUNK)

    def _raw_peekable(self) -> bool:
        """Pull the next raw chunk into the input buffer; False at raw EOF."""
        self._in = self._raw_read()
        return bool(self._in)

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0 or n > _CHUNK:
            n = _CHUNK
        if n == 0 or self._done:
            return b""
        out = self._raw_read_n(n) if self._d is None else self._decompress(n)
        self.total += len(out)
        if self.total > self._limits.max_total:
            raise LimitsExceeded(f"decompressed total exceeds {self._limits.max_total}")
        return out

    def _raw_read_n(self, n: int) -> bytes:
        out = self._raw.read(n)
        if not out:
            self._done = True
        return out

    def _decompress(self, n: int) -> bytes:
        d = self._d
        while True:
            if d.eof:
                if not self._next_member():
                    return b""
                d = self._d
                continue
            if self._kind == "gz":
                if not self._in:
                    self._in = self._raw_read()
                out = self._codec(d.decompress, self._in, n)
                self._in = d.unconsumed_tail
                if not out and not self._in and not d.eof and not self._raw_peekable():
                    raise ParseError("truncated gzip stream")
            else:
                if d.needs_input:
                    if not self._in:
                        self._in = self._raw_read()
                    if not self._in:
                        raise ParseError("truncated bz2 stream")
                    data, self._in = self._in, b""
                else:
                    data = b""
                out = self._codec(d.decompress, data, n)
            if out:
                return out

    @staticmethod
    def _codec(fn, data: bytes, n: int) -> bytes:
        try:
            return fn(data, n)
        except (zlib.error, OSError, EOFError) as exc:
            raise ParseError("corrupt compressed stream") from exc

    def _next_member(self) -> bool:
        """At end of a compressed member: start the next one, or validate padding."""
        rest = self._d.unused_data + self._in
        self._in = b""
        magic = _GZ_MAGIC if self._kind == "gz" else _BZ2_MAGIC
        while len(rest) < len(magic):
            more = self._raw_read()
            if not more:
                break
            rest += more
        if rest.startswith(magic):
            self._d = self._new_decompressor()
            self._in = rest
            return True
        while rest:
            if rest.count(0) != len(rest):
                raise ParseError("trailing data after compressed stream")
            rest = self._raw_read()
        self._done = True
        return False

    def drain(self) -> None:
        """Consume (and count) everything left, so trailing data is validated."""
        while self.read(_CHUNK):
            pass


def _detect(raw: BinaryIO) -> str:
    head = raw.read(4)
    raw.seek(0)
    if head.startswith(_GZ_MAGIC):
        return "gz"
    if head.startswith(_BZ2_MAGIC):
        return "bz2"
    if head.startswith(_ZIP_MAGIC):
        return "zip"
    return "tar"


def _anomaly(kind: str, raw_name: str, detail: str) -> Anomaly:
    return Anomaly(kind=kind, path_hex=to_hex(raw_name)[:_PATH_HEX_MAX], detail=detail)


_DETAILS = {
    "traversal": "name contains a '..' component",
    "absolute_path": "name is absolute or has a drive prefix",
}


def iter_members(
    path: Path,
    ecosystem: str,
    limits: Limits,
    anomalies: list[Anomaly],
    *,
    stats: TarStats | None = None,
) -> Iterator[Member]:
    """Yield regular-file members of an archive, never touching the disk.

    Appends anomalies as a side effect. Raises LimitsExceeded or ParseError;
    any other error from a malformed archive is converted to ParseError.
    """
    stats = stats if stats is not None else TarStats()
    with open(path, "rb") as raw:
        kind = _detect(raw)
        if kind == "zip":
            yield from _iter_zip(raw, ecosystem, limits, anomalies, stats)
            return
        reader = _CountingReader(raw, kind, limits)
        try:
            yield from _iter_tar(reader, ecosystem, limits, anomalies, stats)
            reader.drain()
        except (LimitsExceeded, ParseError):
            raise
        except (MemoryError, RecursionError) as exc:
            raise LimitsExceeded(f"resource exhausted: {type(exc).__name__}") from exc
        except Exception as exc:  # malformed input must never escape raw
            raise ParseError(f"malformed tar: {type(exc).__name__}") from exc
        finally:
            stats.bytes_read = reader.total


def _iter_zip(
    raw: BinaryIO,
    ecosystem: str,
    limits: Limits,
    anomalies: list[Anomaly],
    stats: TarStats,
) -> Iterator[Member]:
    raise NotImplementedError("zip handled in Task 5")
    yield  # pragma: no cover  (makes this a generator)


_META_TYPES = (
    tarfile.XHDTYPE,
    tarfile.XGLTYPE,
    tarfile.SOLARIS_XHDTYPE,
    tarfile.GNUTYPE_LONGNAME,
    tarfile.GNUTYPE_LONGLINK,
)
MAX_META_CHAIN = 16  # metadata headers allowed in front of one real member

# The hooks below rely on tarfile internals of CPython 3.13; fail loudly if an
# upgrade removes them instead of silently losing the metadata caps.
if not callable(getattr(tarfile.TarInfo, "_proc_member", None)):
    raise RuntimeError("tarfile.TarInfo._proc_member missing: review archive.py")


@dataclass
class _TarState:
    meta_chain_bytes: int = 0
    meta_chain_count: int = 0
    global_meta_bytes: int = 0
    bad_header: bool = False


def _guarded_tarinfo(state: _TarState) -> type[tarfile.TarInfo]:
    """TarInfo subclass that caps metadata headers and records bad headers.

    tarfile buffers each pax/GNU-long body in memory and recurses once per
    chained header, so they are capped per header, per chain (reset when a real
    member is returned) and, for global 'g' headers, across the whole archive.
    A header that fails to parse after the first member is remembered: tarfile
    would silently treat it as end-of-archive, other tar readers would not.
    """

    class _GuardedTarInfo(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls, tarfile_obj):
            try:
                info = super().fromtarfile(tarfile_obj)
            except (tarfile.InvalidHeaderError, tarfile.TruncatedHeaderError):
                if tarfile_obj.offset > 0:
                    state.bad_header = True
                raise
            state.meta_chain_bytes = 0
            state.meta_chain_count = 0
            return info

        def _proc_member(self, tarfile_obj):
            if self.type in _META_TYPES:
                if self.size > MAX_META:
                    raise LimitsExceeded(f"metadata header larger than {MAX_META}")
                state.meta_chain_count += 1
                if state.meta_chain_count > MAX_META_CHAIN:
                    raise LimitsExceeded("too many chained metadata headers")
                if self.type == tarfile.XGLTYPE:
                    state.global_meta_bytes += self.size
                    if state.global_meta_bytes > MAX_META:
                        raise LimitsExceeded("global pax headers exceed cap")
                else:
                    state.meta_chain_bytes += self.size
                    if state.meta_chain_bytes > MAX_META:
                        raise LimitsExceeded("chained metadata headers exceed cap")
            return super()._proc_member(tarfile_obj)

    return _GuardedTarInfo


def _check_end_of_archive(tar: tarfile.TarFile, state: _TarState) -> None:
    """Fail closed on anything tarfile would silently ignore after its last member."""
    if state.bad_header:
        raise ParseError("invalid tar header mid-archive")
    # tar.fileobj is tarfile's _Stream: it returns its own buffered bytes first,
    # then pulls (counted, capped) chunks from the _CountingReader.
    while chunk := tar.fileobj.read(_CHUNK):
        if chunk.count(0) != len(chunk):
            raise ParseError("non-zero data after end-of-archive")


def _iter_tar(
    reader: _CountingReader,
    ecosystem: str,
    limits: Limits,
    anomalies: list[Anomaly],
    stats: TarStats,
) -> Iterator[Member]:
    seen: dict[str, int] = {}
    state = _TarState()
    tar = tarfile.open(fileobj=reader, mode="r|", tarinfo=_guarded_tarinfo(state))
    try:
        for index, m in enumerate(tar):
            if index + 1 > limits.max_members:
                raise LimitsExceeded(f"more than {limits.max_members} members")
            if m.isdir():
                continue
            if m.issym() or m.islnk():
                kind = "symlink" if m.issym() else "hardlink"
                anomalies.append(_anomaly("link_skipped", m.name, f"{kind} not read"))
                continue
            sparse = m.sparse is not None or m.type == tarfile.GNUTYPE_SPARSE
            if not m.isreg() or sparse:
                detail = f"unsupported member type {m.type!r}"
                anomalies.append(_anomaly("bad_member", m.name, detail))
                continue
            norm, kinds = normalize_path(m.name, ecosystem)
            for k in kinds:
                anomalies.append(_anomaly(k, m.name, _DETAILS[k]))
            if norm in seen:
                anomalies.append(
                    _anomaly("duplicate_name", m.name, "normalised name repeats")
                )
            seen[norm] = index
            f = tar.extractfile(m)
            data = f.read(limits.max_file + 1) if f is not None else b""
            if len(data) > limits.max_file:
                raise LimitsExceeded(f"member larger than {limits.max_file}")
            stats.files_scanned += 1
            yield Member(index=index, path=norm, data=data)
        _check_end_of_archive(tar, state)
    finally:
        tar.close()
