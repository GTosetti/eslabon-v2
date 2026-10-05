"""In-memory archive builders for tests. Nothing here touches the disk."""

from __future__ import annotations

import bz2
import gzip
import io
import stat
import struct
import tarfile
import warnings
import zipfile
from dataclasses import dataclass

_TYPES = {
    "file": tarfile.REGTYPE,
    "dir": tarfile.DIRTYPE,
    "symlink": tarfile.SYMTYPE,
    "hardlink": tarfile.LNKTYPE,
    "fifo": tarfile.FIFOTYPE,
    "chr": tarfile.CHRTYPE,
    "blk": tarfile.BLKTYPE,
}


@dataclass
class TarItem:
    name: str
    data: bytes = b""
    type: str = "file"
    linkname: str = ""
    pax: dict | None = None


def make_tar(items: list[TarItem], compression: str = "gz") -> bytes:
    """Build a tar archive in memory; compression is "gz", "bz2" or ""."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for item in items:
            info = tarfile.TarInfo(item.name)
            info.type = _TYPES[item.type]
            info.linkname = item.linkname
            info.mtime = 0
            if item.pax:
                info.pax_headers = dict(item.pax)
            if item.type == "file":
                info.size = len(item.data)
                tar.addfile(info, io.BytesIO(item.data))
            else:
                tar.addfile(info)
    raw = buf.getvalue()
    if compression == "gz":
        return gzip.compress(raw, mtime=0)
    if compression == "bz2":
        return bz2.compress(raw)
    if compression == "":
        return raw
    raise ValueError(f"unknown compression {compression!r}")


def ustar_header(name: str, size: int, typeflag: bytes) -> bytes:
    """Hand-craft one valid 512-byte ustar header with a correct checksum."""

    def octal(value: int, width: int) -> bytes:
        return (b"%0*o" % (width - 1, value)) + b"\0"

    header = bytearray(512)
    header[0:100] = name.encode("ascii").ljust(100, b"\0")
    header[100:108] = octal(0o644, 8)
    header[108:116] = octal(0, 8)
    header[116:124] = octal(0, 8)
    header[124:136] = octal(size, 12)
    header[136:148] = octal(0, 12)
    header[148:156] = b" " * 8
    header[156:157] = typeflag
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[148:156] = b"%06o\0 " % sum(header)
    return bytes(header)


def pad_block(data: bytes) -> bytes:
    """Pad data with zeros to a multiple of 512 bytes."""
    return data + bytes(-len(data) % 512)


def pax_record(keyword: str, value: str) -> bytes:
    """One pax record "<len> <keyword>=<value>\n" with a self-consistent length."""
    body = f" {keyword}={value}\n".encode()
    length = len(body) + 1
    while len(str(length)) + len(body) != length:
        length += 1
    return str(length).encode() + body


def ustar_member(name: str, data: bytes, typeflag: bytes = b"0") -> bytes:
    """A hand-crafted header plus its padded data blocks."""
    return ustar_header(name, len(data), typeflag) + pad_block(data)


# ---------------------------------------------------------------- zip ----

_EOCD = struct.Struct("<4s4H2LH")  # 22 bytes
_ZIP64_EOCD = struct.Struct("<4sQ2H2L4Q")  # 56 bytes
_ZIP64_LOC = struct.Struct("<4sLQL")  # 20 bytes


@dataclass
class ZipItem:
    name: str
    data: bytes = b""
    compress: int = zipfile.ZIP_DEFLATED
    symlink: bool = False


def make_zip(items: list[ZipItem], comment: bytes = b"") -> bytes:
    """Build a zip archive in memory. Duplicate names are allowed (on purpose)."""
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns on duplicate names
        with zipfile.ZipFile(buf, "w") as zf:
            for item in items:
                info = zipfile.ZipInfo(item.name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = item.compress
                if item.symlink:
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                zf.writestr(info, item.data)
            zf.comment = comment
    return buf.getvalue()


def _eocd(data: bytes) -> tuple[int, tuple]:
    """Position and fields of the EOCD of an archive built by make_zip."""
    pos = data.rfind(b"PK\x05\x06")
    return pos, _EOCD.unpack_from(data, pos)


def _entry_offsets(data: bytes, name: str) -> list[tuple[int, int]]:
    """(local header offset, central header offset) of every entry called name."""
    _, eocd = _eocd(data)
    cd_size, cd_offset = eocd[5], eocd[6]
    out = []
    pos = cd_offset
    while pos < cd_offset + cd_size:
        n, m, k = struct.unpack_from("<3H", data, pos + 28)
        (local,) = struct.unpack_from("<L", data, pos + 42)
        if data[pos + 46 : pos + 46 + n].decode("cp437") == name:
            out.append((local, pos))
        pos += 46 + n + m + k
    if not out:
        raise KeyError(name)
    return out


def zip_patch_member(
    data: bytes, name: str, *, or_flags: int = 0, method: int | None = None
) -> bytes:
    """Patch flag bits / compression method of `name` in both local and central
    headers. Nothing else is recomputed: zipfile does not checksum headers, and
    it raises on the patched member before it would compare the CRC."""
    buf = bytearray(data)
    for local, central in _entry_offsets(data, name):
        for off_flags, off_method in (
            (local + 6, local + 8),
            (central + 8, central + 10),
        ):
            (flags,) = struct.unpack_from("<H", buf, off_flags)
            struct.pack_into("<H", buf, off_flags, flags | or_flags)
            if method is not None:
                struct.pack_into("<H", buf, off_method, method)
    return bytes(buf)


def zip_patch_crc(data: bytes, name: str, crc: int) -> bytes:
    """Overwrite the stored CRC-32 of `name` (local and central headers)."""
    buf = bytearray(data)
    for local, central in _entry_offsets(data, name):
        struct.pack_into("<L", buf, local + 14, crc)
        struct.pack_into("<L", buf, central + 16, crc)
    return bytes(buf)


def zip_patch_eocd(
    data: bytes, *, entries: int | None = None, cd_size: int | None = None
) -> bytes:
    """Rewrite the declared entry counts / central-directory size of the EOCD."""
    pos, f = _eocd(data)
    f = list(f)
    if entries is not None:
        f[3] = f[4] = entries
    if cd_size is not None:
        f[5] = cd_size
    return data[:pos] + _EOCD.pack(*f) + data[pos + _EOCD.size :]


def zip64_declaring(data: bytes, *, entries: int, cd_size: int | None = None) -> bytes:
    """Replace the EOCD of a comment-less make_zip archive with a self-consistent
    ZIP64 EOCD record + locator + EOCD whose 16/32-bit fields are saturated, so
    the 64-bit record carries `entries` (e.g. 1_000_000) and `cd_size`."""
    pos, f = _eocd(data)
    real_cd_size, cd_offset = f[5], f[6]
    body = data[:pos]
    rec_pos = len(body)
    z64 = _ZIP64_EOCD.pack(
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        entries,
        entries,
        real_cd_size if cd_size is None else cd_size,
        cd_offset,
    )
    loc = _ZIP64_LOC.pack(b"PK\x06\x07", 0, rec_pos, 1)
    eocd = _EOCD.pack(b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return body + z64 + loc + eocd
