"""scripts/measure_fp.py: JSONL parsing and consistency checks, all offline.

The JSONL here is fake and minimal; nothing is fetched or scanned.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

_PATH = Path(__file__).parent.parent / "scripts" / "measure_fp.py"
_spec = importlib.util.spec_from_file_location("measure_fp", _PATH)
assert _spec is not None and _spec.loader is not None
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)


def _summary(status: str = "ok", findings: int = 0) -> dict:
    return {
        "event": {"dataset": "eslabon.scan"},
        "eslabon": {
            "scan": {
                "status": status,
                "findings": findings,
                "anomaly_kinds": [],
                "osv_status": "ok",
                "files_scanned": 1,
                "bytes_read": 10,
                "duration_ms": 5,
            }
        },
    }


def _finding(rule: str = "ESL-003") -> dict:
    return {
        "event": {"dataset": "eslabon.finding"},
        "rule": {"id": rule},
        "eslabon": {
            "evidence": {"file": "a.py", "line": 3, "match_count": 1, "snippet": "x"}
        },
    }


def _write(path: Path, lines: list[str]) -> Path:
    path.write_text("".join(line + "\n" for line in lines), "utf-8")
    return path


def _record(**kw) -> dict:
    rec = {
        "ecosystem": "pypi", "name": "p", "version": "1", "exit_code": 0,
        "status": "ok", "findings": [], "malformed_lines": 0, "wall_s": 1.0,
        "anomaly_kinds": [],
    }
    rec.update(kw)
    return rec


def test_parse_events_reads_summary_and_findings(tmp_path):
    out = _write(
        tmp_path / "a.jsonl", [json.dumps(_finding()), json.dumps(_summary("ok", 1))]
    )
    summary, findings, bad = m._parse_events(out)
    assert summary["eslabon"]["scan"]["status"] == "ok"
    assert [f["rule"] for f in findings] == ["ESL-003"]
    assert bad == 0


def test_parse_events_counts_malformed_lines_instead_of_crashing(tmp_path):
    out = _write(
        tmp_path / "a.jsonl",
        [
            "{not json",
            json.dumps({"event": {"dataset": "eslabon.finding"}}),  # no rule/evidence
            json.dumps([1, 2]),  # not an object
            json.dumps(_summary()),
        ],
    )
    summary, findings, bad = m._parse_events(out)
    assert bad == 3
    assert findings == []
    assert summary is not None


def test_parse_events_missing_file(tmp_path):
    assert m._parse_events(tmp_path / "none.jsonl") == (None, [], 0)


def test_consistent_records_are_not_flagged():
    finding = {"rule": "ESL-001"}
    assert m.inconsistencies(_record()) == []
    assert m.inconsistencies(_record(exit_code=1, findings=[finding])) == []
    assert m.inconsistencies(_record(exit_code=2, status="limits_exceeded")) == []
    # a non-ok scan exits 2 even when it also has findings
    rec = _record(exit_code=2, status="timeout", findings=[finding])
    assert m.inconsistencies(rec) == []


def test_exit_code_disagreeing_with_status_or_findings_is_flagged():
    finding = {"rule": "ESL-001"}
    assert m.inconsistencies(_record(exit_code=1))  # 1 but no findings
    assert m.inconsistencies(_record(exit_code=0, findings=[finding]))
    assert m.inconsistencies(_record(exit_code=0, status="parse_error"))
    assert m.inconsistencies(_record(exit_code=None))  # harness timeout
    assert m.inconsistencies(_record(status="no_summary"))
    assert m.inconsistencies(_record(malformed_lines=2))


def test_report_lists_inconsistent_packages():
    records = [_record(name="good"), _record(name="bad", exit_code=1)]
    text = m.report(records)
    section = text.split("Inconsistent records")[1]
    assert "pypi bad==1" in section
    assert "good" not in section


def test_scan_one_records_malformed_lines(tmp_path, monkeypatch):
    def fake_run(cmd, **kw):
        out = Path(cmd[cmd.index("--out") + 1])
        _write(out, ["garbage", json.dumps(_summary())])
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    pkg = {"ecosystem": "npm", "name": "x", "version": "1.0.0"}
    rec = m.scan_one(pkg, tmp_path / "x.jsonl", 5.0)
    assert rec["malformed_lines"] == 1
    assert rec["status"] == "ok"
    assert m.inconsistencies(rec) == ["1 malformed JSONL line(s)"]
