"""Streaming tar reader: hostile-archive behaviour. Every test checks no disk writes."""

from __future__ import annotations

import bz2
import gzip
import os
import zlib

import pytest
from builders import TarItem, make_tar, ustar_header

from eslabon.archive import TarStats, iter_members, normalize_path
from eslabon.model import Limits, LimitsExceeded, ParseError

ARCHIVE = "pkg.tgz"
SMALL = Limits(max_total=1 * 2**20, max_file=256 * 2**10)
CHUNK = 64 * 2**10


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    yield tmp_path
    assert sorted(os.listdir(tmp_path)) == [ARCHIVE]


def _write(workdir, data: bytes):
    path = workdir / ARCHIVE
    path.write_bytes(data)
    return path


def _run(path, ecosystem="pypi", limits=None, stats=None):
    anomalies = []
    members = list(
        iter_members(path, ecosystem, limits or Limits(), anomalies, stats=stats)
    )
    return members, anomalies


def _kinds(anomalies):
    return [a.kind for a in anomalies]


def test_regular_files_yielded_normalised(workdir):
    path = _write(
        workdir,
        make_tar(
            [
                TarItem("package", type="dir"),
                TarItem("package/index.js", b"console.log(1)"),
                TarItem("package//lib/./a.js", b"a"),
                TarItem("package\\lib\\b.js", b"b"),
            ]
        ),
    )
    stats = TarStats()
    members, anomalies = _run(path, "npm", stats=stats)
    assert [(m.index, m.path, m.data) for m in members] == [
        (1, "index.js", b"console.log(1)"),
        (2, "lib/a.js", b"a"),
        (3, "lib/b.js", b"b"),
    ]
    assert anomalies == []
    assert stats.files_scanned == 3


def test_pypi_keeps_first_component(workdir):
    path = _write(workdir, make_tar([TarItem("pkg-1.0/setup.py", b"x")]))
    members, _ = _run(path, "pypi")
    assert [m.path for m in members] == ["pkg-1.0/setup.py"]


def test_traversal_name_flagged_nothing_written(workdir):
    path = _write(workdir, make_tar([TarItem("../../evil.py", b"import os")]))
    members, anomalies = _run(path)
    assert [(m.path, m.data) for m in members] == [("evil.py", b"import os")]
    assert _kinds(anomalies) == ["traversal"]
    assert anomalies[0].path_hex == b"../../evil.py".hex()
    assert anomalies[0].detail.isascii()


def test_absolute_and_drive_paths_flagged(workdir):
    path = _write(
        workdir,
        make_tar([TarItem("/etc/cron.d/x", b"a"), TarItem("C:\\Windows\\x.py", b"b")]),
    )
    members, anomalies = _run(path)
    assert [m.path for m in members] == ["etc/cron.d/x", "Windows/x.py"]
    assert _kinds(anomalies) == ["absolute_path", "absolute_path"]
    assert anomalies[1].path_hex == b"C:\\Windows\\x.py".hex()


def test_symlink_and_hardlink_skipped_and_counted(workdir):
    path = _write(
        workdir,
        make_tar(
            [
                TarItem("a", type="symlink", linkname="/etc/passwd"),
                TarItem("b", type="hardlink", linkname="/etc/shadow"),
                TarItem("c.py", b"c"),
            ]
        ),
    )
    members, anomalies = _run(path)
    assert [(m.index, m.path) for m in members] == [(2, "c.py")]
    assert _kinds(anomalies) == ["link_skipped", "link_skipped"]
    with pytest.raises(LimitsExceeded):
        _run(path, limits=Limits(max_members=2))


def test_device_and_fifo_are_bad_members(workdir):
    path = _write(
        workdir, make_tar([TarItem("f", type="fifo"), TarItem("d", type="chr")])
    )
    members, anomalies = _run(path)
    assert members == []
    assert _kinds(anomalies) == ["bad_member", "bad_member"]


def test_duplicate_name_flagged(workdir):
    path = _write(
        workdir,
        make_tar(
            [
                TarItem("package/x.js", b"first"),
                TarItem("package/./x.js", b"second"),
            ]
        ),
    )
    members, anomalies = _run(path, "npm")
    assert [(m.index, m.path, m.data) for m in members] == [
        (0, "x.js", b"first"),
        (1, "x.js", b"second"),
    ]
    assert _kinds(anomalies) == ["duplicate_name"]


def test_member_cap(workdir):
    path = _write(workdir, make_tar([TarItem(f"f{i}") for i in range(5001)]))
    with pytest.raises(LimitsExceeded):
        _run(path)


def test_member_cap_exact_limit_ok(workdir):
    path = _write(workdir, make_tar([TarItem(f"f{i}") for i in range(5)]))
    members, _ = _run(path, limits=Limits(max_members=5))
    assert len(members) == 5


def test_per_file_cap(workdir):
    path = _write(workdir, make_tar([TarItem("big", bytes(SMALL.max_file + 1))]))
    with pytest.raises(LimitsExceeded):
        _run(path, limits=SMALL)


def test_per_file_cap_exact_size_ok(workdir):
    path = _write(workdir, make_tar([TarItem("big", bytes(SMALL.max_file))]))
    members, _ = _run(path, limits=SMALL)
    assert len(members[0].data) == SMALL.max_file


def _gzip_zeros_file(path, total: int):
    comp = zlib.compressobj(9, zlib.DEFLATED, 31)
    with path.open("wb") as fh:
        for _ in range(total // CHUNK):
            fh.write(comp.compress(bytes(CHUNK)))
        fh.write(comp.flush())


def test_gzip_bomb(workdir):
    path = workdir / ARCHIVE
    _gzip_zeros_file(path, 2 * 2**20)
    assert path.stat().st_size < 16 * 2**10
    stats = TarStats()
    with pytest.raises(LimitsExceeded):
        _run(path, limits=SMALL, stats=stats)
    assert SMALL.max_total < stats.bytes_read <= SMALL.max_total + CHUNK


def test_gzip_bomb_many_small_files(workdir):
    items = [TarItem(f"f{i}", bytes(250 * 2**10)) for i in range(8)]
    path = _write(workdir, make_tar(items))
    stats = TarStats()
    with pytest.raises(LimitsExceeded):
        _run(path, limits=SMALL, stats=stats)
    assert SMALL.max_total < stats.bytes_read <= SMALL.max_total + CHUNK


def test_pax_header_bomb(workdir):
    path = workdir / ARCHIVE
    with path.open("wb") as fh:
        fh.write(ustar_header("PaxHeader/x", 2 * 2**20, b"x"))
        for _ in range(2 * 2**20 // CHUNK):
            fh.write(bytes(CHUNK))
    stats = TarStats()
    with pytest.raises(LimitsExceeded):
        _run(path, limits=SMALL, stats=stats)
    assert stats.bytes_read <= SMALL.max_total + CHUNK


def test_pax_header_capped_before_buffering(workdir):
    path = workdir / ARCHIVE
    with path.open("wb") as fh:
        fh.write(ustar_header("PaxHeader/x", 2 * 2**20, b"x"))
        for _ in range(2 * 2**20 // CHUNK):
            fh.write(bytes(CHUNK))
    stats = TarStats()
    limits = Limits(max_total=8 * 2**20, max_file=256 * 2**10)
    with pytest.raises(LimitsExceeded):
        _run(path, limits=limits, stats=stats)
    assert stats.bytes_read <= CHUNK


def test_gzip_trailing_garbage_parse_error(workdir):
    path = _write(workdir, make_tar([TarItem("a.py", b"a")]) + b"GARBAGE!")
    with pytest.raises(ParseError):
        _run(path)


def test_truncated_gzip_parse_error(workdir):
    data = make_tar([TarItem("a.py", os.urandom(4096))])
    path = _write(workdir, data[: len(data) // 2])
    with pytest.raises(ParseError):
        _run(path)


def test_concatenated_gzip_members_and_zero_padding_ok(workdir):
    raw = make_tar(
        [TarItem("a.py", b"a" * 3000), TarItem("b.py", b"b" * 3000)], compression=""
    )
    cut = 1500
    data = gzip.compress(raw[:cut]) + gzip.compress(raw[cut:]) + bytes(777)
    path = _write(workdir, data)
    stats = TarStats()
    members, anomalies = _run(path, stats=stats)
    assert [(m.path, m.data) for m in members] == [
        ("a.py", b"a" * 3000),
        ("b.py", b"b" * 3000),
    ]
    assert anomalies == []
    assert stats.bytes_read == len(raw)


def test_concatenated_bz2_members_ok(workdir):
    raw = make_tar([TarItem("a.py", b"a" * 3000)], compression="")
    data = bz2.compress(raw[:700]) + bz2.compress(raw[700:]) + bytes(3)
    path = _write(workdir, data)
    members, _ = _run(path)
    assert [(m.path, m.data) for m in members] == [("a.py", b"a" * 3000)]


def test_plain_tar_counted_against_max_total(workdir):
    raw = make_tar([TarItem("a.py", b"hello")], compression="")
    path = _write(workdir, raw)
    stats = TarStats()
    members, _ = _run(path, stats=stats)
    assert [m.data for m in members] == [b"hello"]
    assert stats.bytes_read == len(raw)
    with pytest.raises(LimitsExceeded):
        _run(path, limits=Limits(max_total=len(raw) - 1))


def test_bz2_supported(workdir):
    path = _write(workdir, make_tar([TarItem("x/y.py", b"bz")], compression="bz2"))
    members, _ = _run(path)
    assert [(m.path, m.data) for m in members] == [("x/y.py", b"bz")]


def test_empty_archive_yields_nothing(workdir):
    path = _write(workdir, make_tar([]))
    stats = TarStats()
    members, anomalies = _run(path, stats=stats)
    assert members == [] and anomalies == []
    assert stats.files_scanned == 0


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not a tar at all" * 100,
        b"\x1f\x8b" + b"\xff" * 50,
        b"BZh9" + b"\x00" * 50,
        ustar_header("a", 10, b"0")[:-1] + b"\x01" + bytes(512),  # bad checksum
    ],
)
def test_malformed_input_is_parse_error(workdir, data):
    path = _write(workdir, data)
    with pytest.raises(ParseError):
        _run(path)


def test_zip_magic_deferred_to_task5(workdir):
    path = _write(workdir, b"PK\x03\x04" + bytes(100))
    with pytest.raises(NotImplementedError):
        _run(path)


@pytest.mark.parametrize(
    ("raw", "eco", "expected", "kinds"),
    [
        ("a\\b\\c.py", "pypi", "a/b/c.py", []),
        ("a//b/./c.py", "pypi", "a/b/c.py", []),
        ("./a.py", "pypi", "a.py", []),
        ("a/../../b.py", "pypi", "a/b.py", ["traversal"]),
        ("/abs.py", "pypi", "abs.py", ["absolute_path"]),
        ("d:/x.py", "pypi", "x.py", ["absolute_path"]),
        ("/../x", "pypi", "x", ["absolute_path", "traversal"]),
        ("package/lib/x.js", "npm", "lib/x.js", []),
        ("x.js", "npm", "x.js", []),
        ("...", "pypi", "...", []),
    ],
)
def test_normalize_path(raw, eco, expected, kinds):
    assert normalize_path(raw, eco) == (expected, kinds)
