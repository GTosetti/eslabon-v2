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
from builders import (
    TarItem,
    ZipItem,
    make_tar,
    make_zip,
    zip_overlap_duplicates,
    zip_patch_member,
    zip_rename,
)

import eslabon.cli as cli
import eslabon.scan as scan
from eslabon.model import Finding, Limits, PackageRef

# CLI scans here get a recorded empty OSV answer (conftest.osv_clean).
pytestmark = pytest.mark.usefixtures("osv_clean")

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
    assert sc["osv_status"] == "ok"
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


def test_duplicate_member_every_copy_reported(dirs, monkeypatch):
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
    assert snippets == ["FIRST copy", "LAST copy"]
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
        b"\xff\xfe\x00garbage",
    ],
    ids=["syntax", "array", "non_str", "no_version", "bad_utf"],
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
    "body",
    [
        b'{"name": "big", "version": "1.0.0", "n": ' + b"9" * 5000 + b"}",
        b'{"name": "big", "version": "1.0.0", "description": "\xff\xc3("}',
        b"\xef\xbb\xbf" + b'{"name": "big", "version": "1.0.0"}',
    ],
    ids=["huge_int", "invalid_utf8", "bom"],
)
def test_npm_metadata_parsed_like_npm(dirs, body):
    # npm: JSON.parse(stripBOM(String(buffer))); String() replaces bad bytes
    # and V8 accepts any number of digits, so the identity must survive.
    target = _put(dirs, "m.tgz", make_tar([TarItem("package/package.json", body)]))
    assert _run(target, dirs[1], "--ecosystem", "npm") == 0
    s = _summary(_events(dirs[1]))
    assert s["package"] == {"name": "big", "version": "1.0.0"}
    assert s["eslabon"]["scan"]["anomaly_kinds"] == []


def test_npm_metadata_too_deep_is_incomplete(dirs):
    # V8's JSON parser is iterative: npm reads this; Python cannot.
    deep = b"[" * 100_000 + b"]" * 100_000
    body = b'{"name": "d", "version": "1.0.0", "x": ' + deep + b"}"
    target = _put(dirs, "m.tgz", make_tar([TarItem("package/package.json", body)]))
    assert _run(target, dirs[1], "--ecosystem", "npm") == 2
    s = _summary(_events(dirs[1]))
    sc = s["eslabon"]["scan"]
    assert sc["status"] == "incomplete"
    assert sc["anomaly_kinds"] == ["package_json_too_deep"]
    assert sc["anomalies"] == 1  # recorded once, not by both readers
    assert "package_json_too_deep" in scan.INCOMPLETE_KINDS


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


# ------------------------------------------------------------- fix round 1 ----


def _flag_evil(member, ctx):
    if b"EVIL" not in member.data:
        return []
    return _one_finding(member, ctx)


def _finding_snippets(events):
    return [
        e["eslabon"]["evidence"]["snippet"]
        for e in events
        if e["event"]["dataset"] == "eslabon.finding"
    ]


def test_r25_tar_traversal_copy_not_hidden_by_later_benign_copy(dirs, monkeypatch):
    # pip writes "top/x/../setup.py" to top/setup.py; the lossy normalised path
    # "top/x/setup.py" must not let the benign second member hide it.
    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [_flag_evil])
    data = make_tar(
        [
            TarItem("top/x/../setup.py", b"EVIL payload"),
            TarItem("top/x/setup.py", b"benign"),
        ]
    )
    target = _put(dirs, "evil-1.0.tar.gz", data)
    assert _run(target, dirs[1], "--ecosystem", "pypi") == 1
    events = _events(dirs[1])
    assert _finding_snippets(events) == ["EVIL payload"]
    assert _summary(events)["eslabon"]["scan"]["status"] == "ok"


def test_r25_wheel_backslash_traversal_copy_is_kept(dirs, monkeypatch):
    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [_flag_evil])
    data = make_zip(
        [
            ZipItem("w/x/.." + chr(0x5C) + "__init__.py", b"EVIL payload"),
            ZipItem("w/x/__init__.py", b"benign"),
        ]
    )
    target = _put(dirs, "w-1.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 1
    assert _finding_snippets(_events(dirs[1])) == ["EVIL payload"]


BS = chr(0x5C)  # backslash: a literal filename character on POSIX installers


@pytest.mark.parametrize(
    ("eco", "items"),
    [
        (
            "pypi",
            [
                TarItem("pkg-1.0/PKG-INFO", b"Name: pkg\nVersion: 1.0\n"),
                TarItem("pkg-1.0/setup.py", b"EVIL payload"),
                TarItem("pkg-1.0" + BS + "setup.py", b"ok"),
            ],
        ),
        (
            "npm",
            [
                TarItem("package/package.json", PKG_JSON),
                TarItem("package/index.js", b"EVIL payload"),
                TarItem("package" + BS + "index.js", b"ok"),
            ],
        ),
        (
            "pypi",
            [
                TarItem("pkg-1.0/PKG-INFO", b"Name: pkg\nVersion: 1.0\n"),
                TarItem("pkg-1.0/pkg/__init__.py", b"EVIL payload"),
                TarItem("pkg-1.0/pkg" + BS + "__init__.py", b"ok"),
            ],
        ),
    ],
    ids=["sdist", "npm", "nested"],
)
def test_r27_backslash_copy_does_not_hide_finding(dirs, monkeypatch, eco, items):
    # On POSIX "\" is a literal character: both files get installed.
    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [_flag_evil])
    target = _put(dirs, "bs.tgz", make_tar(items))
    assert _run(target, dirs[1], "--ecosystem", eco) == 1
    events = _events(dirs[1])
    assert _finding_snippets(events) == ["EVIL payload"]
    assert _summary(events)["eslabon"]["scan"]["status"] == "ok"


def _orig_names(data: bytes) -> list[str]:
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return [i.orig_filename for i in zf.infolist()]


def test_r28_zip_true_backslash_copy_does_not_hide_finding(dirs, monkeypatch):
    # On a Windows host zipfile rewrites "\" to "/" in .filename; the scanner
    # must decide on the stored name (orig_filename), whatever its host OS.
    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [_flag_evil])
    data = make_zip(
        [
            ZipItem("w/pkg/__init__.py", b"EVIL payload"),
            ZipItem("w/pkgX__init__.py", b"ok"),
        ]
    )
    stored = ("w/pkg" + BS + "__init__.py").encode("ascii")
    data = zip_rename(data, "w/pkgX__init__.py", stored)
    assert BS in _orig_names(data)[1]  # really stored with a backslash
    target = _put(dirs, "w-1.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 1
    events = _events(dirs[1])
    assert _finding_snippets(events) == ["EVIL payload"]
    assert _summary(events)["eslabon"]["scan"]["status"] == "ok"


def test_r28_zip_nul_in_name_is_treated_as_rewritten(dirs, monkeypatch):
    # zipfile truncates .filename at NUL, so "w/a.py\0" would look like "w/a.py".
    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [_flag_evil])
    data = make_zip(
        [ZipItem("w/a.py", b"EVIL payload"), ZipItem("w/a.pyZ", b"ok")]
    )
    data = zip_rename(data, "w/a.pyZ", b"w/a.py" + bytes([0]))
    assert _orig_names(data)[1] == "w/a.py" + chr(0)
    target = _put(dirs, "w-1.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 1
    assert _finding_snippets(_events(dirs[1])) == ["EVIL payload"]


def test_r28_zip_backslash_dist_info_metadata_is_ambiguous(dirs):
    data = make_zip(
        [
            ZipItem("w-1.0.dist-info/METADATA", b"Name: w\nVersion: 1.0\n"),
            ZipItem("w-1.0.dist-infoXMETADATA", b"Name: spoof\nVersion: 9\n"),
        ]
    )
    data = zip_rename(
        data, "w-1.0.dist-infoXMETADATA", b"w-1.0.dist-info" + BS.encode() + b"METADATA"
    )
    assert BS in _orig_names(data)[1]
    target = _put(dirs, "w-1.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 0
    s = _summary(_events(dirs[1]))
    assert s["package"]["name"] == "unknown"
    assert "ambiguous_metadata" in s["eslabon"]["scan"]["anomaly_kinds"]
    assert s["eslabon"]["scan"]["status"] == "ok"


def test_r27_backslash_metadata_candidate_is_ambiguous(dirs):
    data = make_tar(
        [
            TarItem("pkg-1.0/PKG-INFO", b"Name: pkg\nVersion: 1.0\n"),
            TarItem("pkg-1.0" + BS + "PKG-INFO", b"Name: spoof\nVersion: 9\n"),
        ]
    )
    target = _put(dirs, "pkg-1.0.tar.gz", data)
    assert _run(target, dirs[1], "--ecosystem", "pypi") == 0
    s = _summary(_events(dirs[1]))
    assert s["package"]["name"] == "unknown"
    assert "ambiguous_metadata" in s["eslabon"]["scan"]["anomaly_kinds"]


def test_r27_traversal_metadata_candidate_is_ambiguous(dirs):
    data = make_zip(
        [
            ZipItem("pkg-1.dist-info/METADATA", b"Name: pkg\nVersion: 1\n"),
            ZipItem("x/../pkg-1.dist-info/METADATA", b"Name: spoof\nVersion: 9\n"),
        ]
    )
    target = _put(dirs, "pkg-1-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 0
    s = _summary(_events(dirs[1]))
    assert s["package"]["name"] == "unknown"
    assert "ambiguous_metadata" in s["eslabon"]["scan"]["anomaly_kinds"]


def test_r29_identical_paths_report_every_copy(dirs, monkeypatch):
    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [_flag_evil])
    data = make_zip(
        [
            ZipItem("w/a.py", b"EVIL first"),
            ZipItem("w//./a.py", b"EVIL last"),  # same file once normalised
        ]
    )
    target = _put(dirs, "w-1.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 1
    assert _finding_snippets(_events(dirs[1])) == ["EVIL first", "EVIL last"]


def test_r29_evil_then_benign_same_name_keeps_finding(dirs, monkeypatch):
    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [_flag_evil])
    data = make_zip([ZipItem("w/a.py", b"EVIL first"), ZipItem("w/a.py", b"benign")])
    target = _put(dirs, "w-1.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 1
    events = _events(dirs[1])
    assert _finding_snippets(events) == ["EVIL first"]
    assert "duplicate_name" in _summary(events)["eslabon"]["scan"]["anomaly_kinds"]


def test_r29_dir_with_data_after_evil_file_keeps_finding(dirs, monkeypatch):
    # probe5: "w/a.py/" with data shares the normalised path of the EVIL w/a.py,
    # but pip installs w/a.py = EVIL. Every copy is reported.
    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [_flag_evil])
    data = make_zip([ZipItem("w/a.py", b"EVIL payload"), ZipItem("w/a.pyZ", b"benign")])
    data = zip_rename(data, "w/a.pyZ", b"w/a.py/")
    assert _orig_names(data) == ["w/a.py", "w/a.py/"]
    target = _put(dirs, "w-1.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 1
    events = _events(dirs[1])
    assert _finding_snippets(events) == ["EVIL payload"]
    sc = _summary(events)["eslabon"]["scan"]
    assert sc["status"] == "ok"
    assert "dir_with_content" in sc["anomaly_kinds"]


def _wheel_meta(name: str) -> bytes:
    return f"Metadata-Version: 2.1\nName: {name}\nVersion: 1\n\n".encode()


def test_r26_wheel_second_dist_info_metadata_is_ambiguous(dirs):
    data = make_zip(
        [
            ZipItem("requestz-1.dist-info/METADATA", _wheel_meta("requestz")),
            ZipItem("zzz.dist-info/METADATA", _wheel_meta("totally-benign")),
        ]
    )
    target = _put(dirs, "requestz-1-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 0
    s = _summary(_events(dirs[1]))
    assert s["package"]["name"] == "unknown"
    kinds = s["eslabon"]["scan"]["anomaly_kinds"]
    assert "ambiguous_metadata" in kinds and "no_metadata" not in kinds


def test_r26_wheel_conflicting_dist_info_dirs_are_ambiguous(dirs):
    data = make_zip(
        [
            ZipItem("requestz-1.dist-info/METADATA", _wheel_meta("requestz")),
            ZipItem("other-2.dist-info/RECORD", b""),
        ]
    )
    target = _put(dirs, "requestz-1-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 0
    s = _summary(_events(dirs[1]))
    assert s["package"]["name"] == "unknown"
    assert "ambiguous_metadata" in s["eslabon"]["scan"]["anomaly_kinds"]


def test_r26_wheel_ignores_pkg_info(dirs):
    data = make_zip(
        [
            ZipItem("requestz-1.dist-info/METADATA", _wheel_meta("requestz")),
            ZipItem("w/PKG-INFO", _wheel_meta("totally-benign")),
        ]
    )
    target = _put(dirs, "requestz-1-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 0
    s = _summary(_events(dirs[1]))
    assert s["package"] == {"name": "requestz", "version": "1"}
    assert "ambiguous_metadata" not in s["eslabon"]["scan"]["anomaly_kinds"]


def test_r26_sdist_ignores_dist_info_metadata(dirs):
    data = make_tar(
        [
            TarItem("real-1/PKG-INFO", _wheel_meta("real")),
            TarItem("real-1/zzz.dist-info/METADATA", _wheel_meta("fake")),
        ]
    )
    target = _put(dirs, "real-1.tar.gz", data)
    assert _run(target, dirs[1], "--ecosystem", "pypi") == 0
    assert _summary(_events(dirs[1]))["package"]["name"] == "real"


def test_r26_sdist_two_pkg_info_is_ambiguous(dirs):
    data = make_tar(
        [
            TarItem("real-1/PKG-INFO", _wheel_meta("real")),
            TarItem("fake-9/PKG-INFO", _wheel_meta("fake")),
        ]
    )
    target = _put(dirs, "real-1.tar.gz", data)
    assert _run(target, dirs[1], "--ecosystem", "pypi") == 0
    s = _summary(_events(dirs[1]))
    assert s["package"]["name"] == "unknown"
    assert "ambiguous_metadata" in s["eslabon"]["scan"]["anomaly_kinds"]


def test_r26_npm_bare_package_json_is_ignored(dirs):
    data = make_tar([TarItem("package.json", PKG_JSON)])  # strip:1 drops it
    target = _put(dirs, "bare.tgz", data)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 0
    s = _summary(_events(dirs[1]))
    assert s["package"]["name"] == "unknown"
    assert "no_metadata" in s["eslabon"]["scan"]["anomaly_kinds"]


def test_r26_npm_two_package_json_is_ambiguous(dirs):
    other = b'{"name": "totally-benign", "version": "9"}'
    data = make_tar(
        [
            TarItem("package/package.json", PKG_JSON),
            TarItem("evil/package.json", other),
        ]
    )
    target = _put(dirs, "two.tgz", data)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 0
    s = _summary(_events(dirs[1]))
    assert s["package"]["name"] == "unknown"
    assert "ambiguous_metadata" in s["eslabon"]["scan"]["anomaly_kinds"]


def test_summary_written_when_worker_launch_raises(dirs, monkeypatch, capsys):
    def boom(fn, args, timeout_s):
        raise OSError("spawn failed")

    monkeypatch.setattr(cli, "run_isolated", boom)
    target = _put(dirs, "clean.tgz", CLEAN_TGZ)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 2
    sc = _summary(_events(dirs[1]))["eslabon"]["scan"]
    assert sc["status"] == "parse_error"
    assert sc["error"] == "worker error: OSError"
    assert "Traceback" not in capsys.readouterr().err


def test_summary_written_when_finding_has_unknown_rule(dirs, monkeypatch):
    def bad_rule(member, ctx):
        return [
            Finding(
                rule_id="ESL-999", file=member.path, member_index=member.index,
                line=1, snippet="", match_count=1, name_hex="",
            )
        ]

    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [bad_rule])
    target = _put(dirs, "clean.tgz", CLEAN_TGZ)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 2
    sc = _summary(_events(dirs[1]))["eslabon"]["scan"]
    assert sc["status"] == "parse_error"
    assert sc["error"] == "event error: KeyError"


def test_real_worker_timeout_exit_2(dirs, monkeypatch):
    monkeypatch.setattr(cli, "Limits", lambda: Limits(worker_timeout_s=0.001))
    target = _put(dirs, "clean.tgz", CLEAN_TGZ)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 2
    sc = _summary(_events(dirs[1]))["eslabon"]["scan"]
    assert sc["status"] == "timeout"


def test_no_metadata_not_added_when_status_not_ok(dirs):
    big = make_tar([TarItem("package/big.js", b"\0" * (Limits().max_file + 1))])
    target = _put(dirs, "big.tgz", big)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 2
    sc = _summary(_events(dirs[1]))["eslabon"]["scan"]
    assert sc["status"] == "limits_exceeded"
    assert "no_metadata" not in sc["anomaly_kinds"]


def test_overlapped_zip_entry_is_not_incomplete(dirs):
    data = make_zip(
        [
            ZipItem("pkg-1.dist-info/METADATA", _wheel_meta("pkg")),
            ZipItem("pkg/a.py", b"same"),
            ZipItem("pkg/a.py", b"same"),
        ]
    )
    data = zip_overlap_duplicates(data, "pkg/a.py")
    target = _put(dirs, "pkg-1-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 0
    sc = _summary(_events(dirs[1]))["eslabon"]["scan"]
    assert sc["status"] == "ok"
    assert "overlapped_entry" in sc["anomaly_kinds"]


def test_fifo_in_sdist_is_not_incomplete(dirs):
    data = make_tar(
        [TarItem("p-1/PKG-INFO", _wheel_meta("p")), TarItem("p-1/fifo", type="fifo")]
    )
    target = _put(dirs, "p-1.tar.gz", data)
    assert _run(target, dirs[1], "--ecosystem", "pypi") == 0
    sc = _summary(_events(dirs[1]))["eslabon"]["scan"]
    assert sc["status"] == "ok"
    assert "special_member" in sc["anomaly_kinds"]


def test_r28_zip_nul_slash_dir_with_content_keeps_finding(dirs, monkeypatch):
    # "w/x.py\0/" looks like a dir as stored, but pip installs w/x.py = EVIL.
    _in_process(monkeypatch)
    monkeypatch.setattr(scan, "ANALYZERS", [_flag_evil])
    data = make_zip([ZipItem("w/x.pyZZ", b"EVIL payload")])
    data = zip_rename(data, "w/x.pyZZ", b"w/x.py" + bytes([0]) + b"/")
    assert _orig_names(data) == ["w/x.py" + chr(0) + "/"]
    target = _put(dirs, "w-1.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 1
    events = _events(dirs[1])
    assert _finding_snippets(events) == ["EVIL payload"]
    sc = _summary(events)["eslabon"]["scan"]
    assert "dir_with_content" in sc["anomaly_kinds"]
    assert sc["files_scanned"] == 1


# ------------------------------------------------------------- ESL-005 ----


def _install_top(monkeypatch, pypi: list[str], npm: list[str]) -> None:
    from eslabon import typosquat

    monkeypatch.setattr(
        typosquat,
        "_OVERRIDE",
        {
            "pypi": typosquat.TopList.from_names(pypi, "pypi"),
            "npm": typosquat.TopList.from_names(npm, "npm"),
        },
    )


def _esl005(events: list[dict]) -> list[dict]:
    return [e for e in events if e.get("rule", {}).get("id") == "ESL-005"]


def test_esl005_e2e_reqeusts_sdist(dirs, monkeypatch):
    _install_top(monkeypatch, ["boto3", "requests", "numpy"], ["react"])
    pkg_info = b"Metadata-Version: 2.1\nName: reqeusts\nVersion: 1.0\n\n"
    data = make_tar([TarItem("reqeusts-1.0/PKG-INFO", pkg_info)])
    target = _put(dirs, "reqeusts-1.0.tar.gz", data)
    assert _run(target, dirs[1], "--ecosystem", "pypi") == 1
    events = _events(dirs[1])
    hits = _esl005(events)
    assert len(hits) == 1
    ev = hits[0]["eslabon"]["evidence"]
    assert ev["file"] == "reqeusts" and ev["line"] == 0
    assert ev["snippet"] == "reqeusts ~ requests (distance 1)"
    assert hits[0]["event"]["severity"] == 5
    s = _summary(events)
    assert s["eslabon"]["identity_source"] == "metadata"
    assert s["eslabon"]["scan"]["findings"] == 1
    assert "identity_mismatch" not in s["eslabon"]["scan"]["anomaly_kinds"]


def test_esl005_no_metadata_wheel_falls_back_to_filename(dirs, monkeypatch):
    _install_top(monkeypatch, ["requests"], [])
    data = make_zip([ZipItem("reqeusts/__init__.py", b"")])
    target = _put(dirs, "reqeusts-1.0-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 1
    events = _events(dirs[1])
    hits = _esl005(events)
    assert [h["eslabon"]["evidence"]["file"] for h in hits] == ["reqeusts"]
    s = _summary(events)
    assert s["eslabon"]["identity_source"] == "filename"
    assert s["package"]["name"] == "unknown"  # package.name stays metadata-only
    assert "no_metadata" in s["eslabon"]["scan"]["anomaly_kinds"]


def test_esl005_ambiguous_metadata_falls_back_to_filename(dirs, monkeypatch):
    _install_top(monkeypatch, ["requests"], [])
    data = make_zip(
        [
            ZipItem("a-1.dist-info/METADATA", _wheel_meta("a")),
            ZipItem("b-1.dist-info/METADATA", _wheel_meta("b")),
        ]
    )
    target = _put(dirs, "requestz-1-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 1
    events = _events(dirs[1])
    assert [h["eslabon"]["evidence"]["file"] for h in _esl005(events)] == ["requestz"]
    s = _summary(events)
    assert s["eslabon"]["identity_source"] == "filename"
    assert "ambiguous_metadata" in s["eslabon"]["scan"]["anomaly_kinds"]


def test_esl005_metadata_filename_mismatch_checks_both(dirs, monkeypatch):
    _install_top(monkeypatch, ["requests", "numpy"], [])
    data = make_zip([ZipItem("nunpy-1.dist-info/METADATA", _wheel_meta("nunpy"))])
    target = _put(dirs, "reqeusts-1-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 1
    events = _events(dirs[1])
    snippets = sorted(h["eslabon"]["evidence"]["snippet"] for h in _esl005(events))
    assert snippets == [
        "nunpy ~ numpy (distance 1)", "reqeusts ~ requests (distance 1)"
    ]
    s = _summary(events)
    assert s["eslabon"]["identity_source"] == "metadata"
    assert s["package"]["name"] == "nunpy"
    sc = s["eslabon"]["scan"]
    assert "identity_mismatch" in sc["anomaly_kinds"]
    assert sc["status"] == "ok"  # a mismatch is not "incomplete"


def test_esl005_mismatch_without_hit_is_only_an_anomaly(dirs, monkeypatch):
    _install_top(monkeypatch, ["requests"], [])
    data = make_zip([ZipItem("alpha-1.dist-info/METADATA", _wheel_meta("alpha"))])
    target = _put(dirs, "omega-1-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 0
    sc = _summary(_events(dirs[1]))["eslabon"]["scan"]
    assert sc["anomaly_kinds"] == ["identity_mismatch"]


def test_esl005_pep503_equal_names_are_no_mismatch(dirs, monkeypatch):
    _install_top(monkeypatch, ["requests"], [])
    data = make_zip(
        [ZipItem("Typing_Ext-1.dist-info/METADATA", _wheel_meta("Typing.Ext"))]
    )
    target = _put(dirs, "typing_ext-1-py3-none-any.whl", data)
    assert _run(target, dirs[1]) == 0
    sc = _summary(_events(dirs[1]))["eslabon"]["scan"]
    assert "identity_mismatch" not in sc["anomaly_kinds"]


@pytest.mark.parametrize("filename", ["evil-react-1.0.0.tgz", "react-1.0.0.tgz"])
def test_esl005_scoped_npm_pack_name_is_no_mismatch(dirs, monkeypatch, filename):
    # npm pack names @evil/react evil-react-1.0.0.tgz; the registry, react-1.0.0.tgz
    _install_top(monkeypatch, [], ["react"])
    body = b'{"name": "@evil/react", "version": "1.0.0"}'
    target = _put(dirs, filename, make_tar([TarItem("package/package.json", body)]))
    assert _run(target, dirs[1], "--ecosystem", "npm") == 1
    events = _events(dirs[1])
    assert [h["eslabon"]["evidence"]["snippet"] for h in _esl005(events)] == [
        "@evil/react ~ react (scope confusion)"
    ]
    sc = _summary(events)["eslabon"]["scan"]
    assert "identity_mismatch" not in sc["anomaly_kinds"]


def test_esl005_no_name_at_all_has_no_identity_source(dirs, monkeypatch):
    _install_top(monkeypatch, [], ["react"])
    target = _put(dirs, "anon.tgz", make_tar([TarItem("package/index.js", b"x")]))
    assert _run(target, dirs[1], "--ecosystem", "npm") == 0
    s = _summary(_events(dirs[1]))
    assert "identity_source" not in s["eslabon"]


def test_esl005_top_name_not_flagged_end_to_end(dirs, monkeypatch):
    _install_top(monkeypatch, [], ["left-pad", "left-pan"])
    target = _put(dirs, "left-pad-1.3.0.tgz", CLEAN_TGZ)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 0
    s = _summary(_events(dirs[1]))
    assert s["eslabon"]["identity_source"] == "metadata"


def test_esl005_runs_even_when_archive_too_big(dirs, monkeypatch):
    # identity is independent of content: the filename is checked without opening it
    _install_top(monkeypatch, [], ["react"])
    monkeypatch.setattr(cli, "Limits", lambda: Limits(max_download=10))
    target = _put(dirs, "raect-1.0.0.tgz", CLEAN_TGZ)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 2
    events = _events(dirs[1])
    assert len(_esl005(events)) == 1
    assert _summary(events)["eslabon"]["identity_source"] == "filename"


def test_esl005_rebuilt_package_suffix_is_no_mismatch(dirs, monkeypatch):
    # pyyaml-6.0-1.tar.gz: the last "-<digit>" would give "pyyaml-6.0"
    _install_top(monkeypatch, ["requests"], [])
    pkg_info = b"Metadata-Version: 2.1\nName: PyYAML\nVersion: 6.0\n\n"
    data = make_tar([TarItem("PyYAML-6.0/PKG-INFO", pkg_info)])
    target = _put(dirs, "pyyaml-6.0-1.tar.gz", data)
    assert _run(target, dirs[1], "--ecosystem", "pypi") == 0
    sc = _summary(_events(dirs[1]))["eslabon"]["scan"]
    assert "identity_mismatch" not in sc["anomaly_kinds"]


def test_esl005_npm_rebuild_suffix_is_no_mismatch(dirs, monkeypatch):
    _install_top(monkeypatch, [], ["react"])
    target = _put(dirs, "left-pad-1.3.0-2.tgz", CLEAN_TGZ)
    assert _run(target, dirs[1], "--ecosystem", "npm") == 0
    sc = _summary(_events(dirs[1]))["eslabon"]["scan"]
    assert "identity_mismatch" not in sc["anomaly_kinds"]
