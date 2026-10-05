"""End-to-end tests for `eslabon scan` on local archives.

Archives are built in memory (builders.py) and written to tmp_path/in; the CLI
may only write its --out file, which lives in tmp_path/out. Every emitted line is
validated against schema/event.schema.json.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import jsonschema
import pytest
from builders import TarItem, ZipItem, make_tar, make_zip, zip_patch_member

import eslabon.cli as cli
import eslabon.scan as scan
from eslabon.model import Finding, Limits, PackageRef

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "schema" / "event.schema.json").read_text("utf-8")
)
PKG_JSON = b'{"name": "left-pad", "version": "1.3.0"}'
CLEAN_TGZ = make_tar(
    [
        TarItem("package/package.json", PKG_JSON),
        TarItem("package/index.js", b"module.exports = 1;\n"),
    ]
)


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    """(input dir, output file). Afterwards the input dir holds only the archive."""
    monkeypatch.chdir(tmp_path)
    indir = tmp_path / "in"
    indir.mkdir()
    out = tmp_path / "out" / "e.jsonl"
    names_before: list[str] = []
    yield indir, out, names_before
    assert sorted(os.listdir(indir)) == sorted(names_before)


def _put(dirs, name: str, data: bytes) -> Path:
    indir, _, names = dirs
    path = indir / name
    path.write_bytes(data)
    names.append(name)
    return path


def _events(out: Path) -> list[dict]:
    raw = out.read_bytes()
    assert raw.endswith(b"\n") and b"\r" not in raw
    events = [json.loads(line) for line in raw.decode("ascii").splitlines()]
    for ev in events:
        jsonschema.validate(ev, SCHEMA)
    return events


def _summary(events: list[dict]) -> dict:
    summaries = [e for e in events if e["event"]["dataset"] == "eslabon.scan"]
    assert len(summaries) == 1
    assert events[-1] is summaries[0]  # summary always goes last
    return summaries[0]


def _run(target: Path, out: Path, *extra: str) -> int:
    return cli.main(["scan", str(target), "--out", str(out), *extra])


def _in_process(monkeypatch, status: str | None = None):
    """Run analyze_archive in-process (so monkeypatched ANALYZERS apply)."""

    def fake(fn, args, timeout_s):
        result = fn(*args)
        if status is not None:
            result.status = status
        return result

    monkeypatch.setattr(cli, "run_isolated", fake)


def _one_finding(member, ctx):
    return [
        Finding(
            rule_id="ESL-003", file=member.path, member_index=member.index, line=1,
            snippet=member.data[:20].decode("ascii", "replace"), match_count=1,
            name_hex=member.path.encode().hex(),
        )
    ]


# ------------------------------------------------------------- happy path ----


def test_scan_clean_archive_exit_0_and_summary_valid(dirs, capsys):
    target = _put(dirs, "clean.tgz", CLEAN_TGZ)
    out = dirs[1]
    assert _run(target, out, "--ecosystem", "npm") == 0
    events = _events(out)
    assert len(events) == 1
    s = _summary(events)
    assert s["event"]["outcome"] == "success"
    assert s["eslabon"]["ecosystem"] == "npm"
    assert len(s["eslabon"]["scan_id"]) == 32
    sc = s["eslabon"]["scan"]
    assert sc["status"] == "ok"
    assert sc["files_scanned"] == 2
    assert sc["bytes_read"] > 0
    assert sc["osv_status"] == "skipped"
    import hashlib

    assert s["file"]["hash"]["sha256"] == hashlib.sha256(CLEAN_TGZ).hexdigest()
    assert capsys.readouterr().err == ""


def test_python_m_eslabon_runs_main(dirs, monkeypatch):
    import runpy
    import sys

    target = _put(dirs, "clean.tgz", CLEAN_TGZ)
    argv = ["eslabon", "scan", str(target), "--ecosystem", "npm", "--out", str(dirs[1])]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("eslabon", run_name="__main__")
    assert exc.value.code == 0
    assert len(_events(dirs[1])) == 1


def test_findings_with_status_ok_exit_1(dirs, monkeypatch):
    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [_one_finding])
    target = _put(dirs, "clean.tgz", CLEAN_TGZ)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 1
    events = _events(dirs[1])
    assert [e["event"]["dataset"] for e in events] == [
        "eslabon.finding", "eslabon.finding", "eslabon.scan",
    ]
    assert events[0]["rule"]["id"] == "ESL-003"
    assert events[0]["package"] == {"name": "left-pad", "version": "1.3.0"}
    assert len({e["eslabon"]["scan_id"] for e in events}) == 1


def test_exit_code_2_wins_over_1(dirs, monkeypatch):
    _in_process(monkeypatch, status="timeout")
    monkeypatch.setattr(scan, "ANALYZERS", [_one_finding])
    target = _put(
        dirs, "one.tgz", make_tar([TarItem("package/package.json", PKG_JSON)])
    )
    assert _run(target, dirs[1], "--ecosystem", "npm") == 2
    events = _events(dirs[1])
    assert [e["event"]["dataset"] for e in events] == [
        "eslabon.finding", "eslabon.scan",
    ]
    assert _summary(events)["eslabon"]["scan"]["status"] == "timeout"


# ------------------------------------------------------------- statuses ----


def test_limits_exceeded_exit_2(dirs):
    big = make_tar([TarItem("package/big.js", b"\0" * (Limits().max_file + 1))])
    target = _put(dirs, "big.tgz", big)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 2
    sc = _summary(_events(dirs[1]))["eslabon"]["scan"]
    assert sc["status"] == "limits_exceeded"
    assert "error" in sc


def test_parse_error_exit_2(dirs):
    target = _put(dirs, "junk.tgz", b"\x1f\x8b" + b"not really gzip" * 10)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 2
    assert _summary(_events(dirs[1]))["eslabon"]["scan"]["status"] == "parse_error"


def test_encrypted_zip_member_is_incomplete_exit_2(dirs):
    data = make_zip(
        [
            ZipItem("pkg-1.0.dist-info/METADATA", b"Name: pkg\nVersion: 1.0\n\n"),
            ZipItem("pkg/secret.py", b"print(1)\n"),
        ]
    )
    data = zip_patch_member(data, "pkg/secret.py", or_flags=0x1)
    target = _put(dirs, "pkg-1.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 2
    s = _summary(_events(dirs[1]))
    assert s["eslabon"]["scan"]["status"] == "incomplete"
    assert "encrypted_member" in s["eslabon"]["scan"]["anomaly_kinds"]
    assert s["event"]["outcome"] == "failure"


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        (["ok"], "ok"),
        (["incomplete", "osv_unavailable", "ok"], "incomplete"),
        (["incomplete", "parse_error"], "parse_error"),
        (["parse_error", "limits_exceeded"], "limits_exceeded"),
        (["limits_exceeded", "timeout"], "timeout"),
        (["fetch_error", "hash_mismatch"], "hash_mismatch"),
        (["osv_unavailable", "fetch_error"], "fetch_error"),
    ],
)
def test_status_precedence(statuses, expected):
    assert scan.worst_status(*statuses) == expected


@pytest.mark.parametrize(
    ("status", "findings", "code"),
    [("ok", 0, 0), ("ok", 3, 1), ("incomplete", 0, 2), ("timeout", 5, 2)],
)
def test_exit_code_mapping(status, findings, code):
    assert cli.exit_code(status, findings) == code


# ------------------------------------------------------------- user errors ----


def test_missing_file_exit_2_one_line_stderr_no_traceback(dirs, capsys):
    out = dirs[1]
    code = _run(Path("does-not-exist") / "nope\x1b[31m.tgz", out, "--ecosystem", "npm")
    assert code == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and err.endswith("\n")
    assert "Traceback" not in err
    assert "\x1b" not in err
    assert not out.exists()


def test_unknown_extension_without_ecosystem_exit_2(dirs, capsys):
    target = _put(dirs, "pkg.tgz", CLEAN_TGZ)
    assert _run(target, dirs[1]) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "Traceback" not in err
    assert not dirs[1].exists()


def test_bad_arguments_exit_2_one_line(capsys):
    assert cli.main(["scan"]) == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert cli.main(["scan", "x.whl", "--ecosystem", "cargo"]) == 2
    assert capsys.readouterr().err.count("\n") == 1


def test_whl_implies_pypi(dirs):
    meta = b"Name: pkg\nVersion: 1.0\n"
    data = make_zip([ZipItem("pkg-1.0.dist-info/METADATA", meta)])
    target = _put(dirs, "pkg-1.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 0
    assert _summary(_events(dirs[1]))["eslabon"]["ecosystem"] == "pypi"


def test_unwritable_out_exit_2_one_line(dirs, capsys):
    target = _put(dirs, "clean.tgz", CLEAN_TGZ)
    out_dir = dirs[0].parent / "out-is-a-dir"
    out_dir.mkdir()
    assert _run(target, out_dir, "--ecosystem", "npm") == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "Traceback" not in err


def test_two_scans_append_to_same_out(dirs):
    target = _put(dirs, "clean.tgz", CLEAN_TGZ)
    out = dirs[1]
    assert _run(target, out, "--ecosystem", "npm") == 0
    assert _run(target, out, "--ecosystem", "npm", "--offline") == 0
    events = _events(out)
    assert len(events) == 2
    ids = [e["eslabon"]["scan_id"] for e in events]
    assert ids[0] != ids[1]


def test_default_out_is_events_jsonl_in_cwd(dirs, tmp_path):
    target = _put(dirs, "clean.tgz", CLEAN_TGZ)
    assert cli.main(["scan", str(target), "--ecosystem", "npm"]) == 0
    assert len(_events(tmp_path / "events.jsonl")) == 1


# ------------------------------------------------------------- duplicates ----


def test_duplicate_member_only_last_copy_reported(dirs, monkeypatch):
    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [_one_finding])
    data = make_tar(
        [
            TarItem("package/package.json", PKG_JSON),
            TarItem("package/index.js", b"FIRST copy"),
            TarItem("package/index.js", b"LAST copy"),
        ]
    )
    target = _put(dirs, "dup.tgz", data)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 1
    events = _events(dirs[1])
    snippets = [
        e["eslabon"]["evidence"]["snippet"]
        for e in events
        if e["event"]["dataset"] == "eslabon.finding"
        and e["eslabon"]["evidence"]["file"] == "index.js"
    ]
    assert snippets == ["LAST copy"]
    assert "duplicate_name" in _summary(events)["eslabon"]["scan"]["anomaly_kinds"]


# ------------------------------------------------------------- size gate ----


def test_local_archive_over_max_download_refused_before_open(dirs, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not be called")

    monkeypatch.setattr(cli, "Limits", lambda: Limits(max_download=100))
    monkeypatch.setattr(cli, "run_isolated", boom)
    monkeypatch.setattr(cli, "_sha256", boom)
    target = _put(dirs, "clean.tgz", CLEAN_TGZ + b"\0" * 200)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 2
    s = _summary(_events(dirs[1]))
    assert s["eslabon"]["scan"]["status"] == "limits_exceeded"
    assert "file" not in s  # archive never opened, so no hash


# ------------------------------------------------------------- metadata ----


def test_local_metadata_read_or_no_metadata_anomaly(dirs):
    target = _put(
        dirs, "anon.tgz", make_tar([TarItem("package/index.js", b"x")])
    )
    assert _run(target, dirs[1], "--ecosystem", "npm") == 0
    s = _summary(_events(dirs[1]))
    assert s["package"] == {"name": "unknown", "version": ""}
    assert "no_metadata" in s["eslabon"]["scan"]["anomaly_kinds"]
    assert s["eslabon"]["scan"]["status"] == "ok"


def test_metadata_from_sdist_pkg_info(dirs):
    pkg_info = b"Metadata-Version: 2.1\nName: evil-pkg\nVersion: 6.6.6\n\nName: body\n"
    data = make_tar(
        [
            TarItem("evil-pkg-6.6.6/PKG-INFO", pkg_info),
            TarItem("evil-pkg-6.6.6/setup.py", b"pass\n"),
        ]
    )
    target = _put(dirs, "evil-pkg-6.6.6.tar.gz", data)
    assert _run(target, dirs[1], "--ecosystem", "pypi") == 0
    s = _summary(_events(dirs[1]))
    assert s["package"] == {"name": "evil-pkg", "version": "6.6.6"}
    assert "no_metadata" not in s["eslabon"]["scan"]["anomaly_kinds"]


def test_metadata_from_wheel_metadata(dirs):
    meta = b"Metadata-Version: 2.1\r\nname: whl-pkg\r\nVERSION: 2.0\r\n\r\n"
    data = make_zip(
        [ZipItem("whl_pkg-2.0.dist-info/METADATA", meta), ZipItem("whl_pkg/a.py", b"")]
    )
    target = _put(dirs, "whl_pkg-2.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 0
    s = _summary(_events(dirs[1]))
    assert s["package"] == {"name": "whl-pkg", "version": "2.0"}


def test_metadata_from_npm_package_json(dirs):
    target = _put(dirs, "clean.tgz", CLEAN_TGZ)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 0
    s = _summary(_events(dirs[1]))
    assert s["package"] == {"name": "left-pad", "version": "1.3.0"}


def test_metadata_is_sanitised(dirs):
    name = "a" + chr(0x1B) + "[31mb" + chr(0x202E) + "c"
    evil = json.dumps({"name": name, "version": "1"}).encode("ascii")
    target = _put(dirs, "e.tgz", make_tar([TarItem("package/package.json", evil)]))
    assert _run(target, dirs[1], "--ecosystem", "npm") == 0
    s = _summary(_events(dirs[1]))
    assert s["package"]["name"] == "abc"


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"[1, 2]",
        b'{"name": 5, "version": "1"}',
        b'{"name": "x"}',
        b"[" * 100_000,
        b"\xff\xfe\x00garbage",
    ],
    ids=["syntax", "array", "non_str", "no_version", "deep_nesting", "bad_utf"],
)
def test_malformed_npm_metadata_is_no_metadata(dirs, body):
    target = _put(
        dirs, "m.tgz", make_tar([TarItem("package/package.json", body)])
    )
    assert _run(target, dirs[1], "--ecosystem", "npm") == 0
    s = _summary(_events(dirs[1]))
    assert "no_metadata" in s["eslabon"]["scan"]["anomaly_kinds"]
    assert s["package"]["name"] == "unknown"


@pytest.mark.parametrize(
    ("path", "body", "expected"),
    [
        ("p-1/PKG-INFO", b"Name: p\nVersion: 1\n", ("p", "1")),
        ("p-1/PKG-INFO", b"Name: p\n", None),
        ("p-1/PKG-INFO", b"garbage without headers", None),
        ("p-1/PKG-INFO", b"\nName: p\nVersion: 1\n", None),  # body, not headers
        ("p-1/p.egg-info/PKG-INFO", b"Name: q\nVersion: 2\n", None),
        ("PKG-INFO", b"Name: q\nVersion: 2\n", None),
        ("p-1.dist-info/METADATA", b"Name: w\nVersion: 3\n", ("w", "3")),
        ("p-1.dist-info/sub/METADATA", b"Name: w\nVersion: 3\n", None),
        ("p-1/setup.py", b"Name: x\nVersion: 1\n", None),
    ],
)
def test_parse_metadata_pypi(path, body, expected):
    from eslabon.model import Member

    assert scan.parse_metadata(Member(0, path, body), "pypi") == expected


def test_parse_metadata_npm_only_top_package_json():
    from eslabon.model import Member

    body = b'{"name": "n", "version": "1"}'
    assert scan.parse_metadata(Member(0, "package.json", body), "npm") == ("n", "1")
    assert scan.parse_metadata(Member(0, "lib/package.json", body), "npm") is None


def test_analyze_archive_runs_in_worker_and_returns_metadata(dirs):
    target = _put(dirs, "clean.tgz", CLEAN_TGZ)
    pkg = PackageRef(None, None, "npm", "")
    result = scan.analyze_archive(target, pkg, Limits())
    assert result.status == "ok"
    assert (result.metadata_name, result.metadata_version) == ("left-pad", "1.3.0")
    assert result.files_scanned == 2
