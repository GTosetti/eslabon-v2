"""In-memory archive builders for tests. Nothing here touches the disk."""

from __future__ import annotations

import bz2
import gzip
import io
import tarfile
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
