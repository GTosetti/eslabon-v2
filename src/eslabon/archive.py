"""Streaming, capped readers for hostile package archives.

Nothing in this module writes to disk or follows links. Every decompressed byte
passes through _CountingReader, which enforces Limits.max_total on what is
actually produced, not on what the headers declare.
"""

from __future__ import annotations

import bz2
import copy
import io
import lzma
import os
import re
import stat
import struct
import tarfile
import warnings
import zipfile
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
_ZIP_EMPTY_MAGIC = b"PK\x05\x06"  # an empty zip is just an EOCD record
_DRIVE = re.compile(r"^[A-Za-z]:")


@dataclass
class TarStats:
    """Counters filled in while iterating (ScanResult.bytes_read / files_scanned)."""

    bytes_read: int = 0
    files_scanned: int = 0
    kind: str = ""  # container detected by iter_members: "zip", "gz", "bz2", ...


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
    if head.startswith(_ZIP_MAGIC) or head.startswith(_ZIP_EMPTY_MAGIC):
        return "zip"
    return "tar"


def _anomaly(kind: str, raw_name: str, detail: str) -> Anomaly:
    return Anomaly(kind=kind, path_hex=to_hex(raw_name)[:_PATH_HEX_MAX], detail=detail)


_UNKNOWN_DETAIL = "unknown typeflag; POSIX extractors install it as a regular file"

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
        stats.kind = kind
        reader = None
        try:
            if kind == "zip":
                yield from _iter_zip(raw, ecosystem, limits, anomalies, stats)
            else:
                reader = _CountingReader(raw, kind, limits)
                yield from _iter_tar(reader, ecosystem, limits, anomalies, stats)
                reader.drain()
        except (LimitsExceeded, ParseError):
            raise
        except (MemoryError, RecursionError) as exc:
            raise LimitsExceeded(f"resource exhausted: {type(exc).__name__}") from exc
        except Exception as exc:  # malformed input must never escape raw
            label = "zip" if kind == "zip" else "tar"
            raise ParseError(f"malformed {label}: {type(exc).__name__}") from exc
        finally:
            if reader is not None:
                stats.bytes_read = reader.total


# ---------------------------------------------------------------- zip ----

_EOCD = struct.Struct("<4s4H2LH")  # end of central directory, 22 bytes
_ZIP64_LOC = struct.Struct("<4sLQL")  # ZIP64 EOCD locator, 20 bytes
_ZIP64_EOCD = struct.Struct("<4sQ2H2L4Q")  # ZIP64 EOCD record, 56 bytes
_ZIP64_LOC_SIG = b"PK\x06\x07"
_ZIP64_EOCD_SIG = b"PK\x06\x06"
_EOCD_SEARCH = 65_557  # max comment (65,535) + EOCD (22): same window as zipfile


def _check_eocd(data: bytes, limits: Limits) -> None:
    """Reject absurd declared sizes before zipfile allocates anything.

    Mirrors zipfile._EndRecData: the comment-less fast path first, then the
    last signature in the search window. A ZIP64 locator in front of the EOCD
    means the 64-bit record is what zipfile will use, so that is what we check.
    """
    n = len(data)
    sig = _ZIP_EMPTY_MAGIC
    if (
        n >= _EOCD.size
        and data[n - _EOCD.size : n - 18] == sig
        and data[-2:] == b"\0\0"
    ):
        pos = n - _EOCD.size
    else:
        pos = data.rfind(sig, max(0, n - _EOCD_SEARCH))
        if pos < 0 or n - pos < _EOCD.size:
            raise ParseError("no end-of-central-directory record")
    fields = _EOCD.unpack_from(data, pos)
    entries, cd_size = max(fields[3], fields[4]), fields[5]
    loc = pos - _ZIP64_LOC.size
    if loc >= 0 and data[loc : loc + 4] == _ZIP64_LOC_SIG:
        reloff = _ZIP64_LOC.unpack_from(data, loc)[2]
        rec = loc - _ZIP64_EOCD.size
        if 0 <= reloff <= rec and data[reloff : reloff + 4] == _ZIP64_EOCD_SIG:
            rec = reloff
        if rec < 0 or data[rec : rec + 4] != _ZIP64_EOCD_SIG:
            raise ParseError("ZIP64 locator without ZIP64 end-of-central-directory")
        z64 = _ZIP64_EOCD.unpack_from(data, rec)
        entries, cd_size = max(z64[6], z64[7]), z64[8]
    if entries > limits.max_members:
        raise LimitsExceeded(f"zip declares {entries} entries")
    if cd_size > limits.max_zip_cd:
        raise LimitsExceeded(f"zip central directory of {cd_size} bytes")


def _lzma_decompressor(f, limits: Limits):
    """LZMA-in-zip: 2-byte version, 2-byte props size, LZMA1 props, raw stream."""
    head = f.read(4)
    if len(head) != 4:
        raise zipfile.BadZipFile("truncated LZMA header")
    (psize,) = struct.unpack("<H", head[2:])
    props = f.read(psize)
    if psize < 5 or len(props) != psize or props[0] >= 9 * 5 * 5:
        raise zipfile.BadZipFile("bad LZMA properties")
    lc, rest = props[0] % 9, props[0] // 9
    lp, pb = rest % 5, rest // 5
    # liblzma allocates the declared dictionary up front. We never produce more
    # than max_file + 2 chunks, so a larger dictionary could never be referenced:
    # clamping it keeps decoding identical and memory bounded.
    declared = int.from_bytes(props[1:5], "little")
    dict_size = max(4096, min(declared, limits.max_file + 2 * _CHUNK))
    flt = {
        "id": lzma.FILTER_LZMA1,
        "dict_size": dict_size,
        "lc": lc,
        "lp": lp,
        "pb": pb,
    }
    return lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[flt])


def _bounded_decompress(d, data: bytes, max_length: int) -> bytes:
    return d.decompress(data, max_length)


def _raw_decompress_chunks(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo, limits: Limits
) -> Iterator[bytes]:
    """bz2/LZMA members, decompressed with max_length.

    zipfile calls decompress(data) without max_length for these methods, so a
    few KiB of input can expand to gigabytes in one call. Instead zipfile is
    asked for the raw compressed bytes (a STORED view of the same entry, so its
    local-header and encryption checks still run) and the output is bounded
    here. Semantics match zipfile: output stops at the declared file_size and
    the CRC-32 is verified at the end.
    """
    view = copy.copy(info)
    view.compress_type = zipfile.ZIP_STORED
    view.file_size = info.compress_size
    del view.CRC  # the stored CRC covers the decompressed data, checked below
    with zf.open(view) as f:
        if info.compress_type == zipfile.ZIP_BZIP2:
            d = bz2.BZ2Decompressor()
        else:
            d = _lzma_decompressor(f, limits)
        left = info.file_size
        crc = 0
        while left > 0 and not d.eof:
            if d.needs_input:
                data = f.read(_CHUNK)
                if not data:
                    break
            else:
                data = b""
            out = _bounded_decompress(d, data, min(_CHUNK, left))
            left -= len(out)
            crc = zlib.crc32(out, crc)
            yield out
    if crc != info.CRC:
        raise zipfile.BadZipFile(f"Bad CRC-32 for file {info.filename!r}")


def _zip_chunks(
    zf: zipfile.ZipFile, info: zipfile.ZipInfo, limits: Limits
) -> Iterator[bytes]:
    if info.compress_type in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
        yield from _raw_decompress_chunks(zf, info, limits)
        return
    # STORED, DEFLATED (zipfile bounds inflate by the requested size) and
    # anything else, which zipfile rejects with NotImplementedError on open.
    with zf.open(info) as f:
        while chunk := f.read(_CHUNK):
            yield chunk


_BAD_MEMBER_ERRORS = (
    zipfile.BadZipFile,
    zlib.error,
    lzma.LZMAError,
    EOFError,
    OSError,
    ValueError,  # includes UnicodeDecodeError on a UTF-8-flagged local name
    struct.error,
)


def _read_zip_member(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limits: Limits,
    anomalies: list[Anomaly],
    stats: TarStats,
) -> bytes | None:
    """_read_zip_member_body, with zipfile's warnings turned into anomalies.

    zipfile only warns (never raises) when two central entries share one local
    header ("Overlapped entries ... possible zip bomb"); under -W error that
    would escape as a ParseError, otherwise it is silent noise on stderr.
    """
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        body = _read_zip_member_body(zf, info, limits, anomalies, stats)
    if any("Overlapped entries" in str(w.message) for w in caught):
        anomalies.append(
            _anomaly("overlapped_entry", info.orig_filename, "overlapped entries")
        )
    return body


def _read_zip_member_body(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limits: Limits,
    anomalies: list[Anomaly],
    stats: TarStats,
) -> bytes | None:
    """Member data, or None after recording an anomaly.

    Bytes count against max_total as they are produced, including those of
    members that fail later (e.g. on a bad CRC), so failures are not free.
    """
    raw_name = info.orig_filename  # stored name, not the host-mapped .filename
    buf = bytearray()
    try:
        for chunk in _zip_chunks(zf, info, limits):
            buf += chunk
            stats.bytes_read += len(chunk)
            if stats.bytes_read > limits.max_total:
                raise LimitsExceeded(f"decompressed total exceeds {limits.max_total}")
            if len(buf) > limits.max_file:
                raise LimitsExceeded(f"member larger than {limits.max_file}")
    except (MemoryError, RecursionError):
        raise
    except NotImplementedError as exc:  # subclass of RuntimeError: keep first
        anomalies.append(_anomaly("unsupported_compression", raw_name, str(exc)))
        return None
    except RuntimeError as exc:
        kind = "encrypted_member" if info.flag_bits & 0x1 else "bad_member"
        anomalies.append(_anomaly(kind, raw_name, type(exc).__name__))
        return None
    except _BAD_MEMBER_ERRORS as exc:
        anomalies.append(_anomaly("bad_member", raw_name, type(exc).__name__))
        return None
    return bytes(buf)


_ZIP_SYMLINK = "symlink mode bit set; pip installs it as a regular file"
_DIR_WITH_CONTENT = (
    "directory-looking entry carries data or is ambiguous; "
    "installers may write it as a file"
)


def _iter_zip(
    raw: BinaryIO,
    ecosystem: str,
    limits: Limits,
    anomalies: list[Anomaly],
    stats: TarStats,
) -> Iterator[Member]:
    if os.fstat(raw.fileno()).st_size > limits.max_download:
        raise LimitsExceeded(f"archive larger than {limits.max_download}")
    data = raw.read(limits.max_download + 1)
    if len(data) > limits.max_download:  # file grew after fstat
        raise LimitsExceeded(f"archive larger than {limits.max_download}")
    _check_eocd(data, limits)
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (MemoryError, RecursionError):
        raise
    except Exception as exc:
        raise ParseError(f"cannot open zip: {type(exc).__name__}") from exc
    with zf:
        infos = zf.infolist()
        # zipfile walks the central directory by size, not by the declared count.
        if len(infos) > limits.max_members:
            raise LimitsExceeded(f"more than {limits.max_members} members")
        seen: dict[str, int] = {}
        for index, info in enumerate(infos):
            # Decide on the name as stored: on Windows zipfile maps os.sep ("\\") to
            # "/" in .filename (and truncates at NUL), so .filename would make the
            # verdict depend on the scanner's host OS. Hence orig_filename here.
            name = info.orig_filename
            # pip lists members by .filename and calls a name ending in "/" a dir.
            # Skip only when the stored and the host-mapped name agree on it and
            # there is no data; any other dir-looking entry may be written as a file.
            stored_dir = name.endswith("/")
            mapped_dir = info.filename.endswith("/")
            if stored_dir and mapped_dir and info.file_size == 0:
                continue  # plain empty directory entry
            if stored_dir or mapped_dir or name.endswith("\\"):
                anomalies.append(_anomaly("dir_with_content", name, _DIR_WITH_CONTENT))
            if stat.S_ISLNK(info.external_attr >> 16):
                # pip ignores zip symlink bits and writes the entry as a regular
                # file, so it must be scanned, not skipped (unlike tar links).
                anomalies.append(_anomaly("zip_symlink", name, _ZIP_SYMLINK))
            norm, kinds = normalize_path(name, ecosystem)
            for k in kinds:
                anomalies.append(_anomaly(k, name, _DETAILS[k]))
            if norm in seen:
                anomalies.append(
                    _anomaly("duplicate_name", name, "normalised name repeats")
                )
            seen[norm] = index
            body = _read_zip_member(zf, info, limits, anomalies, stats)
            if body is None:
                continue
            stats.files_scanned += 1
            yield Member(index=index, path=norm, data=body, raw_path=name)


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
            # POSIX (and CPython, pip < 24.1, extractall without a filter) install
            # an unrecognised typeflag as a regular file, so it must be scanned.
            unknown = m.type not in tarfile.SUPPORTED_TYPES
            sparse = m.sparse is not None or m.type == tarfile.GNUTYPE_SPARSE
            if not unknown and (m.isfifo() or m.ischr() or m.isblk()):
                # Special files carry no content: nothing was left unscanned.
                detail = f"special member type {m.type!r} not read"
                anomalies.append(_anomaly("special_member", m.name, detail))
                continue
            if not unknown and (not m.isreg() or sparse):
                detail = f"unsupported member type {m.type!r}"
                anomalies.append(_anomaly("bad_member", m.name, detail))
                continue
            if unknown:
                anomalies.append(_anomaly("unknown_type", m.name, _UNKNOWN_DETAIL))
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
            yield Member(index=index, path=norm, data=data, raw_path=m.name)
        _check_end_of_archive(tar, state)
    finally:
        tar.close()
