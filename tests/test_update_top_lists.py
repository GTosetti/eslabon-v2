"""scripts/update_top_lists.py: parsing and sanity checks, all offline."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).parent.parent / "scripts" / "update_top_lists.py"
_spec = importlib.util.spec_from_file_location("update_top_lists", _PATH)
assert _spec is not None and _spec.loader is not None
u = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(u)


def _js(names: list[str], var: str = "topDownload") -> bytes:
    body = "".join(f"  '{n}',\n" for n in names)
    return f"export const {var} = [\n{body}]\n".encode()


def test_parse_npm_reads_top_download(monkeypatch):
    monkeypatch.setattr(u, "KEEP", 3)
    got = u.parse_npm(_js(["a", "@b/c", "JSONStream", "d"]))
    assert got == ["a", "@b/c", "JSONStream"]


@pytest.mark.parametrize(
    "data",
    [
        b"export const topDownload = [\n  'a' + x,\n]\n",
        b"export const top = [\n  'a',\n]\n",  # wrong array
        b"export const topDownload = [\n  'a',\n];alert(1)\n",
    ],
)
def test_parse_npm_is_strict(data, monkeypatch):
    monkeypatch.setattr(u, "KEEP", 1)
    with pytest.raises(ValueError):
        u.parse_npm(data)


class _Resp:
    def __init__(self, final_url: str, body: bytes = b"{}"):
        self._url, self._body = final_url, body

    def geturl(self):
        return self._url

    def read(self, n):
        return self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_fetch_refuses_a_redirect_to_http(monkeypatch):
    monkeypatch.setattr(
        u.urllib.request, "urlopen", lambda req, timeout: _Resp("http://evil.example/x")
    )
    with pytest.raises(ValueError, match="https"):
        u.fetch("https://example.org/list.json")


def test_fetch_accepts_https_redirect(monkeypatch):
    resp = _Resp("https://b.example/x", b"ok")
    monkeypatch.setattr(u.urllib.request, "urlopen", lambda req, timeout: resp)
    assert u.fetch("https://a.example/x") == b"ok"


def _list(anchors: list[str], n: int = 1200) -> list[str]:
    return anchors + [f"pkg{i}" for i in range(n - len(anchors))]


def test_sanity_requires_anchor_names():
    good = _list(list(u.ANCHORS["pypi"]))
    u.sanity_check("pypi", good, None)
    with pytest.raises(ValueError, match="anchor"):
        u.sanity_check("pypi", _list(["requests", "numpy", "boto3"]), None)


def test_sanity_refuses_a_list_that_changed_too_much():
    anchors = list(u.ANCHORS["npm"])
    old = _list(anchors)
    new_ok = anchors + [f"pkg{i}" for i in range(600)] + [f"new{i}" for i in range(592)]
    u.sanity_check("npm", new_ok, old)  # 608 of the old top 1,000 kept
    new_bad = anchors + [f"new{i}" for i in range(1192)]
    with pytest.raises(ValueError, match="top 1,000"):
        u.sanity_check("npm", new_bad, old)


def test_measure_typosquat_runs_offline_on_bundled_lists(tmp_path):
    path = Path(__file__).parent.parent / "scripts" / "measure_typosquat.py"
    spec = importlib.util.spec_from_file_location("measure_typosquat", path)
    assert spec is not None and spec.loader is not None
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    pos = tmp_path / "pos.json"
    pos.write_text('{"pypi": [["reqeusts", "X"]], "npm": [["lodahs", "Y"]]}', "utf-8")
    rows = m.measure([pos], list_fp=False)
    assert rows[2].startswith("| pypi |") and "| 1/1 |" in rows[2]
    assert rows[3].startswith("| npm |") and "| 1/1 |" in rows[3]
