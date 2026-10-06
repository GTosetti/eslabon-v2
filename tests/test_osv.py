"""ESL-006 known-malicious: OSV lookups against recorded responses.

Every test here runs offline: an injected ``opener`` replays the recorded OSV
responses in tests/data/osv (shaped like real api.osv.dev answers). conftest.py
makes the real opener raise, so an accidental network call fails loudly. The one
test marked ``network`` talks to the real API (``pytest -m network``).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import jsonschema
import pytest
from builders import TarItem, ZipItem, make_tar, make_zip

import eslabon.cli as cli
from eslabon import osv
from eslabon.sanitize import to_hex

DATA = Path(__file__).parent / "data" / "osv"
SCHEMA = json.loads(
    (Path(__file__).parent.parent / "schema" / "event.schema.json").read_text("utf-8")
)


def _load(name: str) -> bytes:
    return (DATA / name).read_bytes()


class Recorder:
    """Opener replaying recorded bodies in order; keeps every request it saw."""

    def __init__(self, *bodies: bytes, final_url: str = osv.API_URL) -> None:
        self.bodies = list(bodies)
        self.final_url = final_url
        self.calls: list[tuple[str, dict, float]] = []

    def __call__(self, url: str, data: bytes, timeout: float) -> tuple[str, bytes]:
        self.calls.append((url, json.loads(data), timeout))
        body = self.bodies.pop(0) if len(self.bodies) > 1 else self.bodies[0]
        return self.final_url, body


def _boom(url, data, timeout):
    raise OSError("network is down")


# ------------------------------------------------------- query_malicious ----


def test_mal_record_becomes_finding():
    rec = Recorder(_load("mal_paypalize.json"))
    assert osv.query_malicious("paypalize", "1.0.0", "npm", opener=rec) == (
        "ok", ["MAL-2025-28954"],
    )
    url, body, timeout = rec.calls[0]
    assert url == "https://api.osv.dev/v1/query"
    assert body == {
        "package": {"name": "paypalize", "ecosystem": "npm"}, "version": "1.0.0",
    }
    assert timeout == 15

    res = osv.check([("paypalize", "1.0.0")], "npm", opener=Recorder(
        _load("mal_paypalize.json")
    ))
    assert res.status == "ok" and res.error is None
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "ESL-006"
    assert f.file == "<osv>"
    assert f.member_index == -1 and f.line == 0
    assert f.snippet == "MAL-2025-28954: Malicious code in paypalize (npm)"
    assert f.match_count == 1
    assert f.name_hex == to_hex("paypalize")


def test_cve_and_ghsa_ignored():
    rec = Recorder(_load("cve_ghsa_requests.json"))
    assert osv.query_malicious("requests", "2.31.0", "PyPI", opener=rec) == ("ok", [])
    assert rec.calls[0][1]["package"] == {"name": "requests", "ecosystem": "PyPI"}
    res = osv.check([("requests", "2.31.0")], "pypi", opener=rec)
    assert (res.status, res.findings) == ("ok", [])


def test_withdrawn_ignored():
    rec = Recorder(_load("withdrawn_mal.json"))
    assert osv.query_malicious("colorizr", "0.1.0", "PyPI", opener=rec) == ("ok", [])


def test_empty_response_is_ok_and_no_ids():
    assert osv.query_malicious("x-y-z", "1", "npm", opener=Recorder(b"{}")) == (
        "ok", [],
    )


def test_version_omitted_when_unknown():
    rec = Recorder(b"{}")
    osv.query_malicious("paypalize", None, "npm", opener=rec)
    assert rec.calls[0][1] == {"package": {"name": "paypalize", "ecosystem": "npm"}}


def test_pagination_follows_next_page_token():
    rec = Recorder(_load("page1.json"), _load("page2.json"))
    assert osv.query_malicious("reqests", "1.0", "PyPI", opener=rec) == (
        "ok", ["MAL-2024-10101"],
    )
    assert len(rec.calls) == 2
    assert "page_token" not in rec.calls[0][1]
    token = json.loads(_load("page1.json"))["next_page_token"]
    assert rec.calls[1][1]["page_token"] == token
    assert rec.calls[1][1]["package"] == {"name": "reqests", "ecosystem": "PyPI"}


def test_pagination_cap_fails_closed():
    rec = Recorder(_load("page1.json"))  # always hands out another page
    assert osv.query_malicious("reqests", "1.0", "PyPI", opener=rec) == (
        "unavailable", [],
    )
    assert len(rec.calls) == osv.MAX_PAGES
    res = osv.check([("reqests", "1.0")], "pypi", opener=Recorder(_load("page1.json")))
    assert res.status == "unavailable" and res.findings == []
    assert res.error == "osv pagination cap"


@pytest.mark.parametrize(
    "opener",
    [
        _boom,
        Recorder(b"<html>502 Bad Gateway</html>"),
        Recorder(b"[]"),
        Recorder(b'{"vulns": {"id": "MAL-1"}}'),
        Recorder(b'{"vulns": [{"summary": "no id"}]}'),
        Recorder(b'{"vulns": [], "next_page_token": 7}'),
        Recorder(b"[" * 100_000),
        Recorder(_load("mal_paypalize.json"), final_url="http://api.osv.dev/v1/query"),
        Recorder(_load("mal_paypalize.json"), final_url="https://evil.example/v1/q"),
        Recorder(b" " * (osv.MAX_RESPONSE + 1)),
    ],
    ids=[
        "oserror", "not-json", "not-object", "vulns-not-list", "id-missing",
        "bad-token", "deep-json", "redirect-to-http", "redirect-off-host", "too-big",
    ],
)
def test_any_failure_is_unavailable(opener):
    assert osv.query_malicious("paypalize", "1.0.0", "npm", opener=opener) == (
        "unavailable", [],
    )
    res = osv.check([("paypalize", "1.0.0")], "npm", opener=opener)
    assert res.status == "unavailable" and res.findings == []
    assert res.error and res.error.startswith("osv")


def test_hostile_summary_is_cleaned_and_capped():
    doc = json.loads(_load("mal_paypalize.json"))
    doc["vulns"][0]["summary"] = "\x1b[31mred\x1b[0m \u202eevil\n" + "A" * 5000
    res = osv.check(
        [("paypalize", "1.0.0")], "npm", opener=Recorder(json.dumps(doc).encode())
    )
    snippet = res.findings[0].snippet
    assert "\x1b" not in snippet and "\u202e" not in snippet and "\n" not in snippet
    assert snippet.startswith("MAL-2025-28954: red evil")
    assert len(snippet) == 1024


def test_one_finding_per_name_lists_every_mal_id():
    doc = json.loads(_load("mal_paypalize.json"))
    second = dict(doc["vulns"][0], id="MAL-2025-30000", summary="Malicious again")
    doc["vulns"].append(second)
    doc["vulns"].append({"id": "MAL-2025-30001"})  # no summary at all
    res = osv.check(
        [("paypalize", "1.0.0")], "npm", opener=Recorder(json.dumps(doc).encode())
    )
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.match_count == 3
    assert f.snippet == (
        "MAL-2025-28954: Malicious code in paypalize (npm); "
        "MAL-2025-30000: Malicious again; MAL-2025-30001"
    )


def test_check_queries_every_name_one_finding_each():
    rec = Recorder(_load("mal_paypalize.json"))
    res = osv.check([("paypalize", "1.0.0"), ("paypal-ize", None)], "npm", opener=rec)
    assert [c[1]["package"]["name"] for c in rec.calls] == ["paypalize", "paypal-ize"]
    assert "version" not in rec.calls[1][1]
    assert [f.name_hex for f in res.findings] == [
        to_hex("paypalize"), to_hex("paypal-ize"),
    ]


def test_check_with_no_names_queries_nothing():
    res = osv.check([], "npm", opener=_boom)
    assert (res.status, res.findings, res.error) == ("ok", [], None)


def test_read_capped_counts_while_reading():
    assert osv._read_capped(io.BytesIO(b"abc"), 3) == b"abc"
    with pytest.raises(osv.OsvError):
        osv._read_capped(io.BytesIO(b"abcd"), 3)


def test_real_opener_refuses_non_https_url():
    with pytest.raises(osv.OsvError):
        osv.urllib_opener("http://api.osv.dev/v1/query", b"{}", 1)


def test_redirect_handler_refuses_other_hosts_and_http():
    handler = osv._SafeRedirect()
    for url in ("http://api.osv.dev/v1/query", "https://evil.example/v1/query"):
        with pytest.raises(osv.OsvError):
            handler.redirect_request(None, None, 302, "Found", {}, url)


def test_conftest_disables_the_real_opener():
    with pytest.raises(AssertionError):
        osv.DEFAULT_OPENER(osv.API_URL, b"{}", 1)
    # and query_malicious with no opener therefore never reaches the network
    assert osv.query_malicious("paypalize", None, "npm") == ("unavailable", [])


@pytest.mark.network
def test_real_api_requests_2_31_0_has_no_mal():
    status, ids = osv.query_malicious(
        "requests", "2.31.0", "PyPI", opener=osv.urllib_opener
    )
    assert status == "ok"
    assert ids == []


# ----------------------------------------------------------------- cli ----

PAYPALIZE = make_tar(
    [
        TarItem("package/package.json", b'{"name": "paypalize", "version": "1.0.0"}'),
        TarItem("package/index.js", b"module.exports = 1;\n"),
    ]
)


def _events(out: Path) -> list[dict]:
    events = [json.loads(x) for x in out.read_text("ascii").splitlines()]
    for ev in events:
        jsonschema.validate(ev, SCHEMA)
    return events


def _scan(tmp_path, monkeypatch, opener, data=PAYPALIZE, name="paypalize-1.0.0.tgz",
          *extra):
    monkeypatch.setattr(osv, "DEFAULT_OPENER", opener)
    target = tmp_path / name
    target.write_bytes(data)
    out = tmp_path / "out.jsonl"
    code = cli.main(["scan", str(target), "--ecosystem", "npm", "--out", str(out),
                     *extra])
    return code, _events(out)


def test_cli_mal_record_exit_1_one_esl006_event(tmp_path, monkeypatch):
    rec = Recorder(_load("mal_paypalize.json"))
    code, events = _scan(tmp_path, monkeypatch, rec)
    assert code == 1
    found = [e for e in events if e["event"]["dataset"] == "eslabon.finding"]
    assert len(found) == 1
    ev = found[0]
    assert ev["rule"]["id"] == "ESL-006"
    assert ev["event"]["severity"] == 10
    assert ev["threat"]["technique"]["id"] == ["T1195.001"]
    assert ev["eslabon"]["evidence"]["file"] == "<osv>"
    assert ev["eslabon"]["evidence"]["snippet"].startswith("MAL-2025-28954: ")
    assert ev["package"] == {"name": "paypalize", "version": "1.0.0"}
    sc = events[-1]["eslabon"]["scan"]
    assert (sc["status"], sc["osv_status"]) == ("ok", "ok")
    assert rec.calls[0][1] == {
        "package": {"name": "paypalize", "ecosystem": "npm"}, "version": "1.0.0",
    }


def test_network_error_is_unavailable_exit_2(tmp_path, monkeypatch):
    code, events = _scan(tmp_path, monkeypatch, _boom)
    assert code == 2
    assert len(events) == 1
    sc = events[0]["eslabon"]["scan"]
    assert sc["status"] == "osv_unavailable"
    assert sc["osv_status"] == "unavailable"
    assert sc["error"].startswith("osv")
    assert events[0]["event"]["outcome"] == "failure"


def test_offline_skips_and_records_skipped(tmp_path, monkeypatch):
    calls = []

    def never(url, data, timeout):
        calls.append(url)
        raise AssertionError("--offline must not query OSV")

    code, events = _scan(tmp_path, monkeypatch, never, PAYPALIZE,
                         "paypalize-1.0.0.tgz", "--offline")
    assert code == 0
    assert calls == []
    sc = events[0]["eslabon"]["scan"]
    assert (sc["status"], sc["osv_status"]) == ("ok", "skipped")


def test_osv_runs_even_when_the_archive_is_broken(tmp_path, monkeypatch):
    """Breaking the archive must not switch the identity rules off; the worse
    worker status is kept, and the file name is queried with its own version."""
    rec = Recorder(_load("mal_paypalize.json"))
    code, events = _scan(tmp_path, monkeypatch, rec, b"\x1f\x8bjunk" * 10)
    assert code == 2
    assert [e["rule"]["id"] for e in events if "rule" in e] == ["ESL-006"]
    sc = events[-1]["eslabon"]["scan"]
    assert (sc["status"], sc["osv_status"]) == ("parse_error", "ok")
    assert rec.calls[0][1] == {
        "package": {"name": "paypalize", "ecosystem": "npm"}, "version": "1.0.0",
    }


def test_osv_unavailable_does_not_mask_a_worse_status(tmp_path, monkeypatch):
    code, events = _scan(tmp_path, monkeypatch, _boom, b"\x1f\x8bjunk" * 10)
    assert code == 2
    sc = events[-1]["eslabon"]["scan"]
    assert (sc["status"], sc["osv_status"]) == ("parse_error", "unavailable")


def test_filename_name_also_queried_when_it_differs(tmp_path, monkeypatch):
    meta = b"Name: innocent\nVersion: 2.0\n"
    data = make_zip([ZipItem("innocent-2.0.dist-info/METADATA", meta)])
    rec = Recorder(b"{}")
    monkeypatch.setattr(osv, "DEFAULT_OPENER", rec)
    target = tmp_path / "evilpkg-2.0-py3-none-any.whl"
    target.write_bytes(data)
    out = tmp_path / "out.jsonl"
    assert cli.main(["scan", str(target), "--out", str(out)]) == 0
    assert [c[1] for c in rec.calls] == [
        {"package": {"name": "innocent", "ecosystem": "PyPI"}, "version": "2.0"},
        {"package": {"name": "evilpkg", "ecosystem": "PyPI"}, "version": "2.0"},
    ]
    assert _events(out)[-1]["eslabon"]["scan"]["osv_status"] == "ok"


def _scan_rec(tmp_path, monkeypatch, data, name, *extra):
    rec = Recorder(b"{}")
    eco = [] if name.endswith(".whl") else ["--ecosystem", "pypi" if
                                          name.endswith(".tar.gz") else "npm"]
    monkeypatch.setattr(osv, "DEFAULT_OPENER", rec)
    target = tmp_path / name
    target.write_bytes(data)
    out = tmp_path / "out.jsonl"
    code = cli.main(["scan", str(target), "--out", str(out), *eco, *extra])
    return code, _events(out), rec


def test_chalk_filename_version_used_without_package_json(tmp_path, monkeypatch):
    """A version-specific MAL record (chalk 5.6.1) must not hit chalk 5.6.2."""
    data = make_tar([TarItem("package/index.js", b"module.exports = 1;\n")])
    code, events, rec = _scan_rec(tmp_path, monkeypatch, data, "chalk-5.6.2.tgz")
    assert code == 0
    assert [c[1] for c in rec.calls] == [
        {"package": {"name": "chalk", "ecosystem": "npm"}, "version": "5.6.2"},
    ]


def test_wheel_filename_version_parsed(tmp_path, monkeypatch):
    data = make_zip([ZipItem("evilpkg/__init__.py", b"x = 1\n")])
    code, events, rec = _scan_rec(
        tmp_path, monkeypatch, data, "evilpkg-3.1-py3-none-any.whl"
    )
    assert [c[1] for c in rec.calls] == [
        {"package": {"name": "evilpkg", "ecosystem": "PyPI"}, "version": "3.1"},
    ]


def test_sdist_rebuild_suffix_queries_the_metadata_version(tmp_path, monkeypatch):
    data = make_tar([TarItem("pyyaml-6.0/PKG-INFO", b"Name: PyYAML\nVersion: 6.0\n\n")])
    code, events, rec = _scan_rec(tmp_path, monkeypatch, data, "pyyaml-6.0-1.tar.gz")
    assert code == 0
    # same name, two versions: OSV is asked about both (R47), metadata first
    assert [c[1] for c in rec.calls] == [
        {"package": {"name": "PyYAML", "ecosystem": "PyPI"}, "version": "6.0"},
        {"package": {"name": "PyYAML", "ecosystem": "PyPI"}, "version": "6.0-1"},
    ]


def test_nameless_archive_is_osv_unavailable_exit_2(tmp_path, monkeypatch):
    """Ambiguous/missing metadata plus a nameless file name must not pass as
    clean: nothing could be asked, so OSV is unavailable (fail closed)."""
    data = make_tar([TarItem("payload/setup.cfg", b"[x]\n")])
    code, events, rec = _scan_rec(tmp_path, monkeypatch, data, "payload.tar.gz")
    assert code == 2
    assert rec.calls == []
    sc = events[-1]["eslabon"]["scan"]
    # R47: no name is "incomplete" (no_identity), which outranks osv_unavailable
    assert (sc["status"], sc["osv_status"]) == ("incomplete", "unavailable")
    assert "no_identity" in sc["anomaly_kinds"]
    assert sc["error"] == "no package name from metadata or file name"


def test_nameless_archive_offline_is_skipped_by_request(tmp_path, monkeypatch):
    """--offline is the user's explicit opt-out (skipped), but a nameless
    archive is still incomplete: ESL-005 could not run either (R47)."""
    data = make_tar([TarItem("payload/setup.cfg", b"[x]\n")])
    code, events, rec = _scan_rec(
        tmp_path, monkeypatch, data, "payload.tar.gz", "--offline"
    )
    assert code == 2
    assert rec.calls == []
    sc = events[-1]["eslabon"]["scan"]
    assert (sc["status"], sc["osv_status"]) == ("incomplete", "skipped")


def test_broken_top_list_still_runs_osv(tmp_path, monkeypatch):
    from eslabon import typosquat

    def broken(name, ecosystem, top=None):
        raise ValueError("malformed top list")

    monkeypatch.setattr(typosquat, "check", broken)
    code, events, rec = _scan_rec(
        tmp_path, monkeypatch, PAYPALIZE, "paypalize-1.0.0.tgz"
    )
    assert code == 2
    assert len(rec.calls) == 1
    sc = events[-1]["eslabon"]["scan"]
    assert (sc["status"], sc["osv_status"]) == ("parse_error", "ok")


def test_overall_deadline_across_names_and_pages(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(osv, "_clock", lambda: now[0])
    seen = []

    def slow(url, data, timeout):
        seen.append(timeout)
        now[0] += 20
        return osv.API_URL, b"{}"

    res = osv.check([("a-pkg", "1"), ("b-pkg", "1"), ("c-pkg", "1")], "npm",
                    opener=slow)
    assert res.status == "unavailable"
    assert res.error == "osv deadline exceeded"
    assert seen == [15, 10]  # the second request only gets what is left
    assert osv.TOTAL_DEADLINE_S == 30


def test_deadline_also_bounds_pagination(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(osv, "_clock", lambda: now[0])

    def paged(url, data, timeout):
        now[0] += 8
        return osv.API_URL, _load("page1.json")

    assert osv.query_malicious("reqests", "1", "PyPI", opener=paged) == (
        "unavailable", [],
    )
    assert now[0] == 32  # 4 pages, then the deadline, not the 10-page cap


def test_real_opener_sends_user_agent():
    from eslabon import __version__

    req = osv._request(osv.API_URL, b"{}")
    assert req.get_header("User-agent") == f"eslabon/{__version__}"
    assert req.get_method() == "POST"
    assert req.get_header("Content-type") == "application/json"


def test_read_capped_checks_the_deadline(monkeypatch):
    # R47(c): a server dribbling bytes under the socket timeout cannot hold the
    # read past the deadline
    now = [0.0]
    monkeypatch.setattr(osv, "_clock", lambda: now[0])

    class Dribble(io.BytesIO):
        def read(self, n=-1):
            now[0] += 4.0
            return super().read(1)

    with pytest.raises(osv.OsvError, match="deadline"):
        osv._read_capped(Dribble(b"x" * 100), osv.MAX_RESPONSE, deadline=10.0)
    assert now[0] == 12.0
    assert osv._read_capped(Dribble(b"ab"), 3, deadline=100.0) == b"ab"
