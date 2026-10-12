"""Tests for the event schema and the JSON Lines emitter."""

import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from eslabon.catalog import load_catalog
from eslabon.emit import (
    MAX_LINE_BYTES,
    SCHEMA_VERSION,
    finding_event,
    summary_event,
    write_events,
)
from eslabon.model import Anomaly, Finding, PackageRef, ScanResult

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "schema" / "event.schema.json").read_text("utf-8")
)
NOW = datetime(2026, 10, 5, 18, 0, 0, 123000, tzinfo=UTC)
PKG = PackageRef("reqeusts", "1.0.0", "pypi", "ab" * 32)
RULE = load_catalog()["ESL-003"]
STATUSES = [
    "ok", "timeout", "limits_exceeded", "parse_error",
    "hash_mismatch", "fetch_error", "incomplete", "osv_unavailable",
]


def _finding(**kw):
    base = dict(
        rule_id="ESL-003", file="setup.py", member_index=0, line=14,
        snippet="ex" + "ec(base64.b64" + "decode(x))", match_count=2, name_hex="aa",
    )
    base.update(kw)
    return Finding(**base)


def _validate(ev):
    jsonschema.Draft202012Validator(SCHEMA).validate(ev)


def _walk(node):
    if isinstance(node, dict):
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        yield node
        for v in node:
            yield from _walk(v)


def test_finding_event_validates():
    ev = finding_event(_finding(), RULE, PKG, "scan-1", NOW)
    _validate(ev)
    assert ev["@timestamp"] == "2026-10-05T18:00:00.123Z"
    assert ev["event"]["kind"] == "alert"
    assert ev["event"]["severity"] == RULE.severity
    assert ev["rule"]["version"]
    assert ev["threat"]["technique"]["id"] == RULE.techniques
    assert ev["eslabon"]["archive"] == {"sha256": "ab" * 32}
    assert "file" not in ev
    assert ev["eslabon"]["schema_version"] == SCHEMA_VERSION == "1.0"
    assert ev["eslabon"]["evidence"]["file"] == "setup.py"
    assert ev["eslabon"]["mitigation"]["action"] == RULE.action


def test_finding_without_hash_omits_archive():
    pkg = PackageRef("a", "1", "npm", "")
    ev = finding_event(_finding(), RULE, pkg, "s", NOW)
    assert "file" not in ev
    assert "archive" not in ev["eslabon"]
    _validate(ev)


@pytest.mark.parametrize("sha", ["ab" * 32, ""])
def test_no_event_has_top_level_file_key(sha):
    # Wazuh 4.14's wazuh-alerts template maps data.file as keyword, so an
    # object under "file" makes OpenSearch reject the whole alert.
    pkg = PackageRef("a", "1", "pypi", sha)
    r = ScanResult("ok", [_finding()], [Anomaly("traversal", "00", "d")])
    for ev in (finding_event(_finding(), RULE, pkg, "s", NOW),
               summary_event(r, pkg, "s", NOW)):
        _validate(ev)
        assert "file" not in ev
        if sha:
            assert ev["eslabon"]["archive"] == {"sha256": sha}
        else:
            assert "archive" not in ev["eslabon"]


def test_max_line_bytes_fits_wazuh_logcollector():
    # logcollector delivers at most 65,278 bytes plus newline
    assert MAX_LINE_BYTES == 65_000


def test_unknown_package_name():
    pkg = PackageRef(None, None, "pypi", "")
    ev = finding_event(_finding(), RULE, pkg, "s", NOW)
    assert ev["package"]["name"] == "unknown"
    _validate(ev)


@pytest.mark.parametrize("status", STATUSES)
def test_summary_event_validates_each_status(status):
    r = ScanResult(
        status=status, findings=[_finding()],
        anomalies=[Anomaly("traversal", "00", "d"), Anomaly("traversal", "01", "d"),
                   Anomaly("duplicate_name", "02", "d")],
        files_scanned=3, bytes_read=99, osv_status="ok", duration_ms=12,
        error=None if status == "ok" else "boom",
    )
    ev = summary_event(r, PKG, "scan-1", NOW)
    _validate(ev)
    assert ev["event"]["kind"] == "event"
    assert ev["event"]["outcome"] == ("success" if status == "ok" else "failure")
    scan = ev["eslabon"]["scan"]
    assert scan["findings"] == 1
    assert scan["anomalies"] == 3
    assert scan["anomaly_kinds"] == ["duplicate_name", "traversal"]
    assert ("error" in scan) == (status != "ok")
    assert "rule" not in ev and "threat" not in ev


def test_summary_error_is_cleaned_and_capped():
    r = ScanResult("parse_error", [], [], error="\x1b[31m" + "x" * 5000)
    ev = summary_event(r, PKG, "s", NOW)
    assert ev["eslabon"]["scan"]["error"] == "x" * 512


def test_every_line_under_64k(tmp_path):
    f = _finding(snippet="A" * (10 * 2**20))
    out = tmp_path / "e.jsonl"
    write_events([finding_event(f, RULE, PKG, "s", NOW)], out)
    assert out.stat().st_size < MAX_LINE_BYTES


def test_megabyte_path_capped(tmp_path):
    big = "p" * 10**6
    f = _finding(file=big, name_hex="ab" * 500_000)
    ev = finding_event(f, RULE, PKG, "s", NOW)
    assert len(ev["eslabon"]["evidence"]["name_hex"]) == 1024
    r = ScanResult("ok", [f], [Anomaly("traversal", "cd" * 500_000, big)])
    out = tmp_path / "e.jsonl"
    write_events([ev, summary_event(r, PKG, "s", NOW)], out)
    for line in out.read_bytes().split(b"\n")[:-1]:
        assert len(line) < MAX_LINE_BYTES


def test_oversize_line_raises(tmp_path):
    with pytest.raises(ValueError):
        write_events([{"x": "y" * 70000}], tmp_path / "e.jsonl")


def test_line_limit_is_exact(tmp_path):
    # '{"x":"' + payload + '"}' is len(payload) + 8 bytes
    out = tmp_path / "e.jsonl"
    assert write_events([{"x": "y" * (MAX_LINE_BYTES - 9)}], out) == 1
    assert len(out.read_bytes()) == MAX_LINE_BYTES  # line + LF
    with pytest.raises(ValueError):
        write_events([{"x": "y" * (MAX_LINE_BYTES - 8)}], tmp_path / "f.jsonl")
    assert not (tmp_path / "f.jsonl").exists()


def test_no_bom_and_lf_only(tmp_path):
    out = tmp_path / "e.jsonl"
    ev = finding_event(_finding(), RULE, PKG, "s", NOW)
    assert write_events([ev, ev], out) == 2
    raw = out.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in raw
    assert raw.count(b"\n") == 2 and raw.endswith(b"\n")


def test_append_not_truncate(tmp_path):
    out = tmp_path / "e.jsonl"
    ev = finding_event(_finding(), RULE, PKG, "s", NOW)
    write_events([ev], out)
    write_events([ev], out)
    assert len(out.read_text("utf-8").splitlines()) == 2


def test_missing_parent_dir_created(tmp_path):
    out = tmp_path / "a" / "b" / "e.jsonl"
    write_events([finding_event(_finding(), RULE, PKG, "s", NOW)], out)
    assert out.exists()


def test_lone_surrogate_safe(tmp_path):
    f = _finding(file="bad" + chr(0xDC80) + ".py")
    out = tmp_path / "e.jsonl"
    write_events([finding_event(f, RULE, PKG, "s", NOW)], out)
    line = out.read_text("utf-8").splitlines()[0]
    assert line.isascii()
    _validate(json.loads(line))


def test_arrays_contain_only_strings():
    r = ScanResult("ok", [], [Anomaly("traversal", "00", "d")])
    for ev in (finding_event(_finding(), RULE, PKG, "s", NOW),
               summary_event(r, PKG, "s", NOW)):
        arrays = list(_walk(ev))
        assert arrays
        for arr in arrays:
            assert all(isinstance(x, str) for x in arr)


def test_schema_is_valid():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


def _summary():
    return summary_event(ScanResult("ok", [], []), PKG, "s", NOW)


def _del(path):
    def mut(ev):
        node = ev
        for k in path[:-1]:
            node = node[k]
        del node[path[-1]]
    return mut


def _set(path, value):
    def mut(ev):
        node = ev
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
    return mut


FINDING_MUTATIONS = {
    "no_package_name": _del(["package", "name"]),
    "bad_rule_id": _set(["rule", "id"], "ESL-007"),
    "severity_0": _set(["event", "severity"], 0),
    "severity_11": _set(["event", "severity"], 11),
    "technique_not_string": _set(["threat", "technique", "id"], [1]),
    "no_snippet": _del(["eslabon", "evidence", "snippet"]),
    "no_rule": _del(["rule"]),
    "bad_ecosystem": _set(["eslabon", "ecosystem"], "gem"),
    "odd_name_hex": _set(["eslabon", "evidence", "name_hex"], "abc"),
    "upper_name_hex": _set(["eslabon", "evidence", "name_hex"], "AB"),
    "evidence_typo_key": _set(["eslabon", "evidence", "snipet"], "x"),
    "bad_category": _set(["event", "category"], ["package", "other"]),
    "bad_type": _set(["event", "type"], ["start"]),
    "legacy_file_hash": _set(["file"], {"hash": {"sha256": "ab" * 32}}),
    "archive_bad_sha": _set(["eslabon", "archive", "sha256"], "AB" * 32),
    "archive_short_sha": _set(["eslabon", "archive", "sha256"], "ab"),
    "archive_typo_key": _set(["eslabon", "archive", "sha265"], "ab" * 32),
}


@pytest.mark.parametrize("name", sorted(FINDING_MUTATIONS))
def test_finding_schema_rejects(name):
    ev = finding_event(_finding(), RULE, PKG, "s", NOW)
    _validate(ev)
    FINDING_MUTATIONS[name](ev)
    with pytest.raises(jsonschema.ValidationError):
        _validate(ev)


SUMMARY_MUTATIONS = {
    "bogus_status": _set(["eslabon", "scan", "status"], "bogus"),
    "no_status": _del(["eslabon", "scan", "status"]),
    "no_outcome": _del(["event", "outcome"]),
    "bad_outcome": _set(["event", "outcome"], "maybe"),
    "carries_rule": _set(["rule"], {"id": "ESL-001"}),
    "carries_threat": _set(["threat"], {"technique": {"id": ["T1"]}}),
    "scan_typo_key": _set(["eslabon", "scan", "file_scanned"], 1),
    "no_scan": _del(["eslabon", "scan"]),
}


@pytest.mark.parametrize("name", sorted(SUMMARY_MUTATIONS))
def test_summary_schema_rejects(name):
    ev = _summary()
    _validate(ev)
    SUMMARY_MUTATIONS[name](ev)
    with pytest.raises(jsonschema.ValidationError):
        _validate(ev)


def test_naive_datetime_rejected():
    naive = datetime(2026, 10, 5, 18, 0, 0)
    with pytest.raises(ValueError):
        finding_event(_finding(), RULE, PKG, "s", naive)
    with pytest.raises(ValueError):
        summary_event(ScanResult("ok", [], []), PKG, "s", naive)


def test_worst_case_non_bmp_expansion(tmp_path):
    emoji = chr(0x1F600)
    f = _finding(file=emoji * 512, snippet=emoji * 1024, name_hex="ab" * 600)
    pkg = PackageRef(emoji * 600, emoji * 600, "pypi", "ab" * 32)
    r = ScanResult("parse_error", [f], [], error=emoji * 600)
    out = tmp_path / "e.jsonl"
    write_events(
        [finding_event(f, RULE, pkg, "s", NOW), summary_event(r, pkg, "s", NOW)], out
    )
    for line in out.read_bytes().split(b"\n")[:-1]:
        assert len(line) < MAX_LINE_BYTES


# Elasticsearch rejects a keyword value longer than 32,766 UTF-8 bytes
# (max_bytes_length_exceeded); the wazuh-alerts template maps strings as keyword
# with no ignore_above, so one such field drops the whole alert (lab experiment D).
ES_KEYWORD_MAX_BYTES = 32_766
ALL_ANOMALY_KINDS = [
    "traversal", "absolute_path", "link_skipped", "zip_symlink", "duplicate_name",
    "encrypted_member", "unsupported_compression", "bad_member", "unknown_type",
    "weak_hash_sha1", "no_metadata", "ambiguous_metadata", "special_member",
    "overlapped_entry", "dir_with_content", "bad_package_json",
    "package_json_too_deep", "identity_mismatch", "no_identity", "temp_leftover",
]
# Widest encodings per character: non-BMP (4 bytes), BMP above U+07FF (3 bytes),
# and a lone surrogate (3 bytes under surrogatepass). Plain ASCII too: with
# ensure_ascii a non-ASCII char costs 6-12 line bytes, so only ASCII can put
# more than 32,766 bytes in one field and still fit the 65,000-byte line.
WORST_CHARS = ["A", chr(0x1F600), chr(0xFFFD), chr(0xDC80)]


def _strings(node):
    if isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)
    elif isinstance(node, str):
        yield node


@pytest.mark.parametrize("ch", WORST_CHARS)
def test_every_emitted_string_fits_es_keyword(ch, tmp_path):
    huge = ch * 10**6
    pkg = PackageRef(huge, huge, "npm", "ab" * 32)
    f = _finding(file=huge, snippet=huge, name_hex="ab" * 10**6)
    anomalies = [Anomaly(k, "cd" * 10**6, huge) for k in ALL_ANOMALY_KINDS]
    events = []
    for rule in load_catalog().values():
        events.append(finding_event(f, rule, pkg, "s" * 64, NOW))
    for status in STATUSES:
        for source in ("metadata", "filename", "argument", None):
            r = ScanResult(
                status, [f], anomalies, files_scanned=2**31, bytes_read=2**40,
                osv_status="unavailable", duration_ms=2**31, error=huge,
                identity_source=source,
            )
            events.append(summary_event(r, pkg, "s" * 64, NOW))
    write_events(events, tmp_path / "e.jsonl")
    checked = 0
    for ev in events:
        for s in _strings(ev):
            size = len(s.encode("utf-8", errors="surrogatepass"))
            assert size <= ES_KEYWORD_MAX_BYTES
            checked += 1
    assert checked > 1000
