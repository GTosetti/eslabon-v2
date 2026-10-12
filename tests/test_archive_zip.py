"""Zip/wheel reader: hostile-archive behaviour. Every test checks no disk writes."""

from __future__ import annotations

import zipfile

import pytest
from builders import (
    ZipItem,
    make_zip,
    zip64_declaring,
    zip_overlap_duplicates,
    zip_patch_crc,
    zip_patch_eocd,
    zip_patch_member,
    zip_rename,
)

import eslabon.archive as archive_mod
from eslabon.archive import TarStats, iter_members
from eslabon.model import Limits, LimitsExceeded, ParseError

ARCHIVE = "pkg-1.0-py3-none-any.whl"
SMALL = Limits(max_total=1 * 2**20, max_file=256 * 2**10)


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


def _forbid_zipfile(monkeypatch):
    def boom(*args, **kwargs):
        pytest.fail("zipfile.ZipFile must not be called")

    monkeypatch.setattr(archive_mod.zipfile, "ZipFile", boom)


def test_wheel_members_yielded(workdir):
    path = _write(
        workdir,
        make_zip(
            [
                ZipItem("pkg/", b""),
                ZipItem("pkg/__init__.py", b"import os"),
                ZipItem("pkg/data.bin", b"raw", compress=zipfile.ZIP_STORED),
                ZipItem("pkg-1.0.dist-info/METADATA", b"Name: pkg"),
                ZipItem("pkg/b.py", b"bz" * 100, compress=zipfile.ZIP_BZIP2),
                ZipItem("pkg/l.py", b"lz" * 100, compress=zipfile.ZIP_LZMA),
            ]
        ),
    )
    stats = TarStats()
    members, anomalies = _run(path, "pypi", stats=stats)
    assert [(m.index, m.path, m.data) for m in members] == [
        (1, "pkg/__init__.py", b"import os"),
        (2, "pkg/data.bin", b"raw"),
        (3, "pkg-1.0.dist-info/METADATA", b"Name: pkg"),
        (4, "pkg/b.py", b"bz" * 100),
        (5, "pkg/l.py", b"lz" * 100),
    ]
    assert anomalies == []
    assert stats.files_scanned == 5
    assert stats.bytes_read == 9 + 3 + 9 + 200 + 200


def test_npm_strips_first_component(workdir):
    path = _write(workdir, make_zip([ZipItem("package/index.js", b"x")]))
    members, _ = _run(path, "npm")
    assert [m.path for m in members] == ["index.js"]


def test_empty_zip_yields_nothing(workdir):
    data = make_zip([])
    assert data.startswith(b"PK\x05\x06")
    path = _write(workdir, data)
    assert _run(path) == ([], [])


def test_zip_declaring_million_entries_rejected_before_parse(workdir, monkeypatch):
    data = zip64_declaring(make_zip([ZipItem("a.py", b"x")]), entries=1_000_000)
    path = _write(workdir, data)
    _forbid_zipfile(monkeypatch)
    with pytest.raises(LimitsExceeded):
        _run(path)


def test_zip64_central_directory_size_rejected_before_parse(workdir, monkeypatch):
    data = zip64_declaring(make_zip([ZipItem("a.py", b"x")]), entries=1, cd_size=2**40)
    path = _write(workdir, data)
    _forbid_zipfile(monkeypatch)
    with pytest.raises(LimitsExceeded):
        _run(path)


def test_eocd_entries_over_cap_rejected_before_parse(workdir, monkeypatch):
    items = [ZipItem(f"f{i}", b"") for i in range(3)]
    path = _write(workdir, make_zip(items))
    _forbid_zipfile(monkeypatch)
    with pytest.raises(LimitsExceeded):
        _run(path, limits=Limits(max_members=2))


def test_eocd_cd_size_over_cap_rejected_before_parse(workdir, monkeypatch):
    path = _write(workdir, make_zip([ZipItem("a.py", b"x")]))
    _forbid_zipfile(monkeypatch)
    with pytest.raises(LimitsExceeded):
        _run(path, limits=Limits(max_zip_cd=10))


def test_member_cap_enforced_on_parsed_entries_not_only_eocd(workdir):
    # EOCD lies (declares 1 entry) but the central directory holds 3.
    data = zip_patch_eocd(
        make_zip([ZipItem(f"f{i}", b"") for i in range(3)]), entries=1
    )
    path = _write(workdir, data)
    with pytest.raises(LimitsExceeded):
        _run(path, limits=Limits(max_members=2))


def test_member_cap_exact_limit_ok(workdir):
    path = _write(workdir, make_zip([ZipItem(f"f{i}", b"") for i in range(2)]))
    members, _ = _run(path, limits=Limits(max_members=2))
    assert len(members) == 2


def test_directories_count_toward_member_cap(workdir):
    path = _write(workdir, make_zip([ZipItem("d/"), ZipItem("d/a"), ZipItem("e/")]))
    with pytest.raises(LimitsExceeded):
        _run(path, limits=Limits(max_members=2))


def test_encrypted_member_is_anomaly_not_crash(workdir):
    data = make_zip([ZipItem("secret.py", b"evil"), ZipItem("ok.py", b"ok")])
    path = _write(workdir, zip_patch_member(data, "secret.py", or_flags=0x1))
    members, anomalies = _run(path)
    assert [m.path for m in members] == ["ok.py"]
    assert _kinds(anomalies) == ["encrypted_member"]


def test_unsupported_compression_is_anomaly(workdir):
    data = make_zip([ZipItem("d64.py", b"x" * 50), ZipItem("ok.py", b"ok")])
    path = _write(workdir, zip_patch_member(data, "d64.py", method=9))
    members, anomalies = _run(path)
    assert [m.path for m in members] == ["ok.py"]
    assert _kinds(anomalies) == ["unsupported_compression"]


def test_unknown_compression_method_is_anomaly(workdir):
    data = make_zip([ZipItem("w.py", b"x" * 50)])
    path = _write(workdir, zip_patch_member(data, "w.py", method=99))
    members, anomalies = _run(path)
    assert members == []
    assert _kinds(anomalies) == ["unsupported_compression"]


@pytest.mark.parametrize(
    "compress",
    [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA],
)
def test_bad_crc_is_bad_member(workdir, compress):
    data = make_zip(
        [ZipItem("a.py", b"hello" * 20, compress=compress), ZipItem("b.py", b"b")]
    )
    path = _write(workdir, zip_patch_crc(data, "a.py", 0x12345678))
    members, anomalies = _run(path)
    assert [m.path for m in members] == ["b.py"]
    assert _kinds(anomalies) == ["bad_member"]


def test_corrupt_deflate_stream_is_bad_member(workdir):
    data = bytearray(make_zip([ZipItem("a.py", b"A" * 1000)]))
    start = 30 + len("a.py")
    data[start : start + 4] = b"\xff\xff\xff\xff"
    path = _write(workdir, bytes(data))
    members, anomalies = _run(path)
    assert members == []
    assert _kinds(anomalies) == ["bad_member"]


def test_zip_traversal_flagged_nothing_written(workdir):
    path = _write(workdir, make_zip([ZipItem("../../evil.py", b"import os")]))
    members, anomalies = _run(path)
    assert [m.path for m in members] == ["evil.py"]
    assert _kinds(anomalies) == ["traversal"]


def test_zip_absolute_and_drive_paths_flagged(workdir):
    path = _write(
        workdir, make_zip([ZipItem("/etc/x", b"1"), ZipItem("C:/win/y", b"2")])
    )
    members, anomalies = _run(path)
    assert [m.path for m in members] == ["etc/x", "win/y"]
    assert _kinds(anomalies) == ["absolute_path", "absolute_path"]


def test_zip_symlink_bit_is_read_as_regular_file(workdir):
    # pip ignores zip symlink mode bits and installs the entry as a regular
    # file, so skipping it would hide importable code.
    path = _write(
        workdir,
        make_zip(
            [ZipItem("evil.py", b"import os", symlink=True), ZipItem("a.py", b"a")]
        ),
    )
    members, anomalies = _run(path)
    assert [(m.index, m.path, m.data) for m in members] == [
        (0, "evil.py", b"import os"),
        (1, "a.py", b"a"),
    ]
    assert _kinds(anomalies) == ["zip_symlink"]
    assert "pip installs it as a regular file" in anomalies[0].detail


def test_zip_symlink_member_still_capped(workdir):
    path = _write(
        workdir,
        make_zip([ZipItem("big", bytes(SMALL.max_file + 1), symlink=True)]),
    )
    with pytest.raises(LimitsExceeded):
        _run(path, limits=SMALL)


@pytest.mark.filterwarnings("error")
def test_overlapped_entries_recorded_no_warning_leaks(workdir, recwarn):
    data = make_zip([ZipItem("a.py", b"same"), ZipItem("a.py", b"same")])
    path = _write(workdir, zip_overlap_duplicates(data, "a.py"))
    members, anomalies = _run(path)
    assert [m.data for m in members] == [b"same", b"same"]
    overlap = [a for a in anomalies if a.detail == "overlapped entries"]
    assert [a.kind for a in overlap] == ["overlapped_entry"]  # was scanned
    assert "duplicate_name" in _kinds(anomalies)
    assert len(recwarn) == 0


def test_zip_duplicate_name_flagged(workdir):
    path = _write(workdir, make_zip([ZipItem("a.py", b"1"), ZipItem("a.py", b"2")]))
    members, anomalies = _run(path)
    assert [(m.index, m.data) for m in members] == [(0, b"1"), (1, b"2")]
    assert _kinds(anomalies) == ["duplicate_name"]


@pytest.mark.parametrize(
    "compress",
    [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA],
)
def test_per_file_cap(workdir, compress):
    path = _write(
        workdir, make_zip([ZipItem("big", bytes(SMALL.max_file + 1), compress)])
    )
    with pytest.raises(LimitsExceeded):
        _run(path, limits=SMALL)


@pytest.mark.parametrize(
    "compress",
    [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA],
)
def test_per_file_cap_exact_size_ok(workdir, compress):
    path = _write(workdir, make_zip([ZipItem("big", bytes(SMALL.max_file), compress)]))
    members, _ = _run(path, limits=SMALL)
    assert len(members[0].data) == SMALL.max_file


@pytest.mark.parametrize("compress", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_bz2_lzma_bomb_bounded(workdir, compress, monkeypatch):
    # 64 MiB of zeros compresses to a few KiB; the reader must stop at the cap
    # without ever materialising the whole member.
    path = _write(workdir, make_zip([ZipItem("bomb", bytes(64 * 2**20), compress)]))
    limits = Limits(max_file=1 * 2**20)
    biggest = []
    real = archive_mod._bounded_decompress

    def spy(*args, **kwargs):
        out = real(*args, **kwargs)
        biggest.append(len(out))
        return out

    monkeypatch.setattr(archive_mod, "_bounded_decompress", spy)
    with pytest.raises(LimitsExceeded):
        _run(path, limits=limits)
    assert biggest and max(biggest) <= archive_mod._CHUNK


def test_max_total_over_sum_of_members(workdir):
    items = [ZipItem(f"f{i}", bytes(200 * 2**10)) for i in range(6)]
    path = _write(workdir, make_zip(items))
    stats = TarStats()
    with pytest.raises(LimitsExceeded):
        _run(path, limits=SMALL, stats=stats)
    assert stats.bytes_read > SMALL.max_total


def test_file_over_max_download_rejected(workdir, monkeypatch):
    path = _write(workdir, make_zip([ZipItem("a.py", bytes(1000), zipfile.ZIP_STORED)]))
    _forbid_zipfile(monkeypatch)
    with pytest.raises(LimitsExceeded):
        _run(path, limits=Limits(max_download=500))


@pytest.mark.parametrize(
    "data",
    [
        b"PK\x03\x04" + b"\x00" * 100,  # no EOCD at all
        b"PK\x03\x04" + b"\x00" * 10 + b"PK\x05\x06\x00",  # truncated EOCD
    ],
    ids=["no_eocd", "truncated_eocd"],
)
def test_zip_without_eocd_is_parse_error(workdir, data):
    path = _write(workdir, data)
    with pytest.raises(ParseError):
        _run(path)


def test_bad_central_directory_is_parse_error_with_cause(workdir):
    data = bytearray(make_zip([ZipItem("a.py", b"a")]))
    cd = data.rfind(b"PK\x01\x02")
    data[cd : cd + 4] = b"XXXX"
    path = _write(workdir, bytes(data))
    with pytest.raises(ParseError) as info:
        _run(path)
    assert isinstance(info.value.__cause__, zipfile.BadZipFile)


def test_zip64_locator_without_record_is_parse_error(workdir):
    data = zip64_declaring(make_zip([ZipItem("a.py", b"x")]), entries=1)
    rec = data.rfind(b"PK\x06\x06")
    data = data[:rec] + b"XXXX" + data[rec + 4 :]
    path = _write(workdir, data)
    with pytest.raises(ParseError):
        _run(path)


def test_valid_zip64_eocd_is_read(workdir):
    data = zip64_declaring(make_zip([ZipItem("a.py", b"x")]), entries=1)
    path = _write(workdir, data)
    members, _ = _run(path)
    assert [(m.path, m.data) for m in members] == [("a.py", b"x")]


def test_zip_with_comment_is_read(workdir):
    path = _write(workdir, make_zip([ZipItem("a.py", b"x")], comment=b"PK hello" * 10))
    members, _ = _run(path)
    assert [m.path for m in members] == ["a.py"]


def test_unexpected_error_becomes_parse_error(workdir, monkeypatch):
    path = _write(workdir, make_zip([ZipItem("a.py", b"x")]))

    def boom(*args, **kwargs):
        raise KeyError("surprise")

    monkeypatch.setattr(archive_mod, "normalize_path", boom)
    with pytest.raises(ParseError):
        _run(path)


def test_memory_error_becomes_limits_exceeded(workdir, monkeypatch):
    path = _write(workdir, make_zip([ZipItem("a.py", b"x")]))

    def boom(*args, **kwargs):
        raise MemoryError

    monkeypatch.setattr(archive_mod, "normalize_path", boom)
    with pytest.raises(LimitsExceeded):
        _run(path)


def test_zip_raw_path_is_stored_name_not_host_mapped(workdir):
    # zipfile maps os.sep to "/" in .filename on Windows; raw_path must not.
    raw = "a/b" + chr(0x5C) + "c.py"
    data = make_zip([ZipItem("a/bXc.py", b"x")])
    data = zip_rename(data, "a/bXc.py", raw.encode("ascii"))
    path = _write(workdir, data)
    members, _ = _run(path)
    assert [(m.path, m.raw_path) for m in members] == [("a/b/c.py", raw)]


def _orig(data: bytes) -> list[str]:
    import io

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return [i.orig_filename for i in zf.infolist()]


def test_zip_nul_slash_name_with_data_is_read_not_skipped(workdir):
    # Stored "w/x.py\0/": .filename is truncated at NUL to "w/x.py" (pip reads it
    # through namelist() and installs w/x.py), so it must not be skipped as a dir.
    raw = "w/x.py" + chr(0) + "/"
    data = make_zip([ZipItem("w/x.pyZZ", b"EVIL")])
    data = zip_rename(data, "w/x.pyZZ", raw.encode("ascii"))
    assert _orig(data) == [raw]
    members, anomalies = _run(_write(workdir, data))
    assert [(m.raw_path, m.data) for m in members] == [(raw, b"EVIL")]
    assert "dir_with_content" in _kinds(anomalies)


def test_zip_backslash_dir_name_with_data_is_read(workdir):
    # Stored "w\\" with content: a literal file on Linux pip, "w/" only on Windows.
    raw = "w" + chr(0x5C)
    data = make_zip([ZipItem("wZ", b"EVIL")])
    data = zip_rename(data, "wZ", raw.encode("ascii"))
    assert _orig(data) == [raw]
    members, anomalies = _run(_write(workdir, data))
    assert [(m.raw_path, m.data) for m in members] == [(raw, b"EVIL")]
    assert "dir_with_content" in _kinds(anomalies)


def test_zip_slash_dir_with_data_is_read(workdir):
    data = make_zip([ZipItem("w/a/", b"EVIL")])
    assert _orig(data) == ["w/a/"]
    members, anomalies = _run(_write(workdir, data))
    assert [m.data for m in members] == [b"EVIL"]
    assert "dir_with_content" in _kinds(anomalies)


def test_zip_empty_dir_entry_is_silently_skipped(workdir):
    data = make_zip([ZipItem("w/", b""), ZipItem("w/a.py", b"x")])
    assert _orig(data) == ["w/", "w/a.py"]
    stats = TarStats()
    members, anomalies = _run(_write(workdir, data), stats=stats)
    assert [m.raw_path for m in members] == ["w/a.py"]
    assert anomalies == []
    assert stats.files_scanned == 1
