"""ESL-003 encoded-exec: YARA engine and rule.

Every malicious-looking source is assembled from tokens at test runtime, so no
committed file contains the literal pattern. The payload only decodes to
``print('eslabon-fixture')``; nothing here is ever executed.
"""

from __future__ import annotations

import base64
import json
import os
import random
from pathlib import Path

import jsonschema
import pytest
import yara
from builders import TarItem, make_tar

import eslabon.cli as cli
import eslabon.scan as scan
from eslabon import npm_scripts, yara_engine
from eslabon.model import (
    Limits,
    LimitsExceeded,
    Member,
    PackageRef,
    ParseError,
    ScanContext,
)
from eslabon.sanitize import to_hex

# CLI scans here get a recorded empty OSV answer (conftest.osv_clean).
pytestmark = pytest.mark.usefixtures("osv_clean")

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "schema" / "event.schema.json").read_text("utf-8")
)
PAYLOAD_B64 = base64.b64encode(b"print('eslabon-fixture')").decode("ascii")
EX = "ex" + "ec"
EV = "ev" + "al"
B64D = "b64" + "decode"
LONG_B64 = base64.b64encode(b"print('eslabon-fixture')" * 4).decode("ascii")
PAYLOAD_HEX = b"print('eslabon-fixture')".hex()


def _py_setup() -> bytes:
    """A setup.py whose evaluator wraps a decoder (built from tokens)."""
    lines = [
        "import base64",
        "from setuptools import setup",
        "",
        EX + "(base64." + B64D + "('" + PAYLOAD_B64 + "'))",
        "setup(name='demo', version='0.0.1', url='https://example.invalid/')",
        "",
    ]
    return "\n".join(lines).encode("ascii")


def _js_index() -> bytes:
    lines = [
        "'use strict';",
        "const u = 'https://example.invalid/';",
        EV + "(at" + "ob('" + PAYLOAD_B64 + "'));",
        "",
    ]
    return "\n".join(lines).encode("ascii")


@pytest.fixture(scope="module")
def ctx() -> ScanContext:
    pkg = PackageRef("demo", "0.0.1", "pypi", "")
    return ScanContext(rules=yara_engine.compile_rules(), limits=Limits(), pkg=pkg)


def _member(path: str, data: bytes, index: int = 3, raw: str = "") -> Member:
    return Member(index=index, path=path, data=data, raw_path=raw)


# ------------------------------------------------------------- the rule ----


def test_py_exec_b64_fires(ctx):
    m = _member("demo-0.0.1/setup.py", _py_setup(), raw="demo-0.0.1/setup.py")
    found = yara_engine.scan_member(m, ctx)
    assert len(found) == 1
    f = found[0]
    assert f.rule_id == "ESL-003"
    assert f.file == "demo-0.0.1/setup.py"
    assert f.member_index == 3
    assert f.line == 4
    assert EX + "(base64." + B64D in f.snippet
    assert f.match_count == 1
    assert f.name_hex == to_hex("demo-0.0.1/setup.py")


def test_js_eval_atob_fires(ctx):
    found = yara_engine.scan_member(_member("index.js", _js_index()), ctx)
    assert [f.rule_id for f in found] == ["ESL-003"]
    assert found[0].line == 3
    assert found[0].name_hex == to_hex("index.js")  # falls back to path


@pytest.mark.parametrize(
    "src",
    [
        EX + "(zlib.decom" + "press(blob))",
        EX + "(bytes.from" + "hex('7072696e74'))",
        "compile(base64.decode" + "bytes(x), 'f', 'exec')",
        "new Func" + "tion(Buffer.from(s, 'base" + "64').toString())()",
        "window." + EV + "  ( at" + "ob (s))",
        # Buffer literal longer than 50 chars: the commonest npm shape
        EV + "(Buffer.from('" + LONG_B64 + "', 'base" + "64').toString())",
        EV + "(Buffer.from('" + PAYLOAD_HEX + "', 'hex').toString())",
        "Func" + "tion(Buffer.from(s, 'BASE" + "64').toString())()",
        EX + "(base64.b32" + "decode(s))",
        EX + "(binascii.a2b_" + "base64(s))",
        EX + "(codecs." + "decode(s, 'rot13'))",
        EX + "(lzma.decom" + "press(blob))",
        EX + "(binascii.unhex" + "lify(s))",
        EV + "(base64.a85" + "decode(s))",
        EX + "(codecs." + "decode(s, 'base" + "64'))",
        "window." + EV + "(at" + "ob(s))",
    ],
)
def test_other_shapes_fire(ctx, src):
    found = yara_engine.scan_member(_member("x", src.encode("ascii")), ctx)
    assert [f.rule_id for f in found] == ["ESL-003"]


def test_b64_data_without_evaluator_silent(ctx):
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4).decode()
    src = (
        "import base64\n"
        "ICON = base64." + B64D + "(\n    '" + png + "'\n)\n"
        "def show():\n    return ICON\n"
    )
    assert yara_engine.scan_member(_member("pkg/icon.py", src.encode()), ctx) == []


@pytest.mark.parametrize(
    "src",
    [
        # evaluator and decoder too far apart (gap is bounded at 50)
        EX + "(" + "x" * 60 + "base64." + B64D + "(s))",
        # split across lines: documented residual gap
        "code = base64." + B64D + "(s)\n" + EX + "(code)\n",
        # a safe evaluator that only parses literals
        "ast.literal_" + EV + "(base64." + B64D + "(s).decode())",
        # method calls named like an evaluator (re.compile, model.eval)
        "re.compile(codecs." + "decode(pat, 'unicode_escape'))",
        "model." + EV + "(base64." + B64D + "(s))",
        "obj." + EX + "(zlib.decom" + "press(b))",
    ],
)
def test_non_adjacent_or_safe_is_silent(ctx, src):
    assert yara_engine.scan_member(_member("x.py", src.encode()), ctx) == []


def test_several_matches_merge_into_one_finding(ctx):
    one = EX + "(base64." + B64D + "('" + PAYLOAD_B64 + "'))\n"
    js = EV + "(at" + "ob('" + PAYLOAD_B64 + "'))\n"
    data = ("# header\n" + one + "pass\n" + one + js).encode()
    found = yara_engine.scan_member(_member("mix.py", data), ctx)
    assert len(found) == 1
    assert found[0].match_count == 3  # two python + one js instance
    assert found[0].line == 2  # the lowest offset wins


def test_rules_compile_with_error_on_warning():
    rules = yara_engine.compile_rules()
    assert isinstance(rules, yara.Rules)
    names = [r.identifier for r in rules]
    assert names, "no rules compiled"
    for r in rules:
        assert r.meta.get("esl_id", "").startswith("ESL-")
    rule_dir = Path(yara_engine.__file__).parent / "rules"
    files = sorted(rule_dir.glob("*.yar"))
    assert [p.stem for p in files] == ["esl001", "esl002", "esl003", "esl004"]
    for p in files:
        yara.compile(filepath=str(p), error_on_warning=True)
        assert p.read_bytes().isascii()


def test_binary_member_no_crash(ctx):
    rnd = random.Random(1337)  # noqa: S311 - test data, not crypto
    elf = b"\x7fELF\x02\x01\x01\x00" + bytes(8)
    noise = bytes(rnd.getrandbits(8) for _ in range(64 * 1024))
    assert yara_engine.scan_member(_member("lib/_x.so", elf + noise), ctx) == []
    # a match embedded in binary: the snippet decodes with replacement, no crash
    hit = (EX + "(base64." + B64D + "('" + PAYLOAD_B64 + "'))").encode()
    data = elf + noise[:500] + b"\x1b[2J\xff\xfe" + hit + noise[500:900]
    found = yara_engine.scan_member(_member("lib/_x.so", data), ctx)
    assert len(found) == 1
    snip = found[0].snippet
    assert chr(0xFFFD) in snip
    assert chr(0x1B) not in snip and "\n" not in snip
    assert len(snip) <= 1024


def test_empty_member_and_no_rules(ctx):
    assert yara_engine.scan_member(_member("e.py", b""), ctx) == []
    no_rules = ScanContext(rules=None, limits=Limits(), pkg=ctx.pkg)
    assert yara_engine.scan_member(_member("s.py", _py_setup()), no_rules) == []


# ------------------------------------------------------------ errors ----


class _Raises:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.timeout = None

    def match(self, data, timeout):
        self.timeout = timeout
        raise self.exc


def test_yara_timeout_becomes_limits_exceeded(ctx):
    fake = _Raises(yara.TimeoutError("slow"))
    c = ScanContext(rules=fake, limits=Limits(yara_timeout_s=7), pkg=ctx.pkg)
    with pytest.raises(LimitsExceeded):
        yara_engine.scan_member(_member("s.py", b"x"), c)
    assert fake.timeout == 7


def test_other_yara_error_becomes_parse_error(ctx):
    c = ScanContext(rules=_Raises(yara.Error("boom")), limits=Limits(), pkg=ctx.pkg)
    with pytest.raises(ParseError, match="yara error: Error"):
        yara_engine.scan_member(_member("s.py", b"x"), c)


# ------------------------------------------------------- registration ----


def test_registered_at_import_and_rules_cached():
    assert yara_engine.scan_member in scan.ANALYZERS
    first = scan._get_rules()
    assert isinstance(first, yara.Rules)
    assert scan._get_rules() is first


def test_cli_end_to_end_setup_py(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    tgz = make_tar(
        [
            TarItem(
                "demo-0.0.1/PKG-INFO",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 0.0.1\n\n",
            ),
            TarItem("demo-0.0.1/setup.py", _py_setup()),
        ]
    )
    target = tmp_path / "demo-0.0.1.tar.gz"
    target.write_bytes(tgz)
    out = tmp_path / "out" / "e.jsonl"
    code = cli.main(["scan", str(target), "--out", str(out), "--ecosystem", "pypi"])
    assert code == 1
    events = [json.loads(x) for x in out.read_text("ascii").splitlines()]
    for ev in events:
        jsonschema.validate(ev, SCHEMA)
    findings = [e for e in events if e["event"]["dataset"] == "eslabon.finding"]
    assert len(findings) == 1
    ev = findings[0]
    assert ev["rule"]["id"] == "ESL-003"
    assert ev["eslabon"]["evidence"]["line"] == 4
    assert ev["eslabon"]["evidence"]["file"] == "demo-0.0.1/setup.py"


def test_whitespace_padded_evaluators_do_not_time_out(ctx):
    # Overlapping \s* and .{0,50} made each hit spawn many regex fibers: 10 MiB
    # of this took over 20 s. Padding must not turn a member into a timeout.
    unit = (EV + "(" + " " * 40).encode("ascii")
    data = unit * (2 * 2**20 // len(unit))
    c = ScanContext(rules=ctx.rules, limits=Limits(yara_timeout_s=2), pkg=ctx.pkg)
    assert yara_engine.scan_member(_member("min.js", data), c) == []


def test_black_formatted_call_fires(ctx):
    nl = chr(10)
    src = nl.join(
        [
            "import base64",
            EX + "(",
            "    base64." + B64D + "(",
            "        '" + PAYLOAD_B64 + "'",
            "    )",
            ")",
            "",
        ]
    )
    found = yara_engine.scan_member(_member("setup.py", src.encode("ascii")), ctx)
    assert [f.rule_id for f in found] == ["ESL-003"]
    assert found[0].line == 2
    crlf = src.replace(nl, chr(13) + nl).encode("ascii")
    assert len(yara_engine.scan_member(_member("setup.py", crlf), ctx)) == 1


_SKIP_DIRS = {
    ".venv", ".git", "__pycache__", ".superpowers", ".pytest_cache", ".ruff_cache",
    "build", "dist",
}
# Repo files that legitimately do what a rule detects. Each entry names the rule
# that fires and why; the file is still matched, and only that rule is excused.
_EXPECTED_HITS = {
    # downloads the two top-name JSON lists for ESL-005 with urllib: a real
    # network call, which is exactly what esl001_py_network is meant to report
    "scripts/update_top_lists.py": {"esl001_py_network"},
    # ESL-006 itself: POSTs to api.osv.dev with urllib (a real network call)
    "src/eslabon/osv.py": {"esl001_py_network"},
}


def test_repo_files_do_not_trip_the_rules():
    # Our own rules (and AV/GitHub scanners) would flag committed literals, so
    # every repo file is matched against the shipped rules themselves. The
    # script-only esl002 namespace matches any URL and only ever sees decoded
    # lifecycle script strings, so it is checked on those (repo package.json
    # files, if any) rather than on raw file bytes.
    rules = yara_engine.compile_rules()
    root = Path(__file__).parent.parent
    hits = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in _SKIP_DIRS and not d.endswith(".egg-info")
        ]
        for name in filenames:
            path = Path(dirpath) / name
            if path.stat().st_size > 10 * 2**20:
                continue
            data = path.read_bytes()
            # the same post-filter the engine applies (ESL-004 public-IP check)
            rel = path.relative_to(root).as_posix()
            excused = _EXPECTED_HITS.get(rel, set())
            matched = [x for x in rules.match(data=data) if x.rule not in excused]
            if any(yara_engine.counted_offsets(x) for x in matched):
                hits.append(rel)
            if name == "package.json":
                m = Member(0, "package.json", data, "package/package.json")
                pkg = PackageRef(None, None, "npm", "")
                ctx = ScanContext(None, Limits(), pkg, "npm")
                if npm_scripts.scan_package_json(m, ctx):
                    hits.append(path.relative_to(root).as_posix())
    assert hits == [], f"files matching the shipped rules: {hits}"


def test_line_is_the_evaluator_line_not_the_preceding_break(ctx):
    nl = chr(10)
    src = "x = 1" + nl + EX + "(base64." + B64D + "(s))" + nl
    found = yara_engine.scan_member(_member("a.py", src.encode("ascii")), ctx)
    assert found[0].line == 2
    found = yara_engine.scan_member(_member("a.py", src[6:].encode("ascii")), ctx)
    assert found[0].line == 1  # evaluator at offset 0 (start of data)


def test_expected_repo_hits_are_not_stale():
    # an excuse that no longer matches must be removed, not kept "just in case"
    rules = yara_engine.compile_rules()
    root = Path(__file__).parent.parent
    for rel, excused in _EXPECTED_HITS.items():
        fired = {m.rule for m in rules.match(data=(root / rel).read_bytes())}
        assert excused <= fired, (rel, excused - fired)
