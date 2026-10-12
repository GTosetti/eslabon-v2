"""Tests for the isolated worker.

Helper functions are module-level because the spawn start method pickles them by
reference and re-imports this module in the child. Keep this module free of
import-time side effects.
"""

from __future__ import annotations

import os
import time

from eslabon.model import Anomaly, Finding, ScanResult
from eslabon.worker import run_isolated


def _ok_result(name: str) -> ScanResult:
    return ScanResult(
        status="ok",
        findings=[
            Finding(
                rule_id="rule-1",
                file=name,
                member_index=0,
                line=7,
                snippet="x" + chr(0x202E) + "y",
                match_count=2,
                name_hex=name.encode().hex(),
            )
        ],
        anomalies=[Anomaly(kind="traversal", path_hex="2e2e2f", detail="d")],
        files_scanned=3,
        bytes_read=99,
        metadata_name="pkg",
        metadata_version="1.0",
    )


def _sleeper(seconds: float) -> ScanResult:
    time.sleep(seconds)
    return ScanResult(status="ok", findings=[], anomalies=[])


def _crasher(code: int) -> ScanResult:
    os._exit(code)


def _raiser(msg: str) -> ScanResult:
    raise ValueError(msg)


def test_returns_child_result():
    res = run_isolated(_ok_result, ("a.py",), timeout_s=60)
    expected = _ok_result("a.py")
    assert res.status == "ok"
    assert res.findings == expected.findings
    assert res.anomalies == expected.anomalies
    assert res.files_scanned == 3
    assert res.bytes_read == 99
    assert res.metadata_name == "pkg"
    assert res.metadata_version == "1.0"
    assert res.error is None
    assert res.duration_ms >= 0


def test_timeout_gives_timeout_status_never_ok():
    t0 = time.monotonic()
    res = run_isolated(_sleeper, (30,), timeout_s=2)
    elapsed = time.monotonic() - t0
    assert res.status == "timeout"
    assert res.error == "worker timeout"
    assert res.findings == []
    assert res.anomalies == []
    assert elapsed < 10
    assert res.duration_ms >= 2000


def test_child_crash_is_parse_error_not_ok_and_fast():
    t0 = time.monotonic()
    res = run_isolated(_crasher, (3,), timeout_s=60)
    elapsed = time.monotonic() - t0
    assert res.status == "parse_error"
    assert "3" in res.error
    assert res.error == "worker exited with code 3"
    assert res.findings == []
    assert elapsed < 10


def test_raising_fn_is_parse_error_with_type_name_only():
    secret = "attacker-controlled-" + chr(0x202E) + "payload"
    t0 = time.monotonic()
    res = run_isolated(_raiser, (secret,), timeout_s=60)
    elapsed = time.monotonic() - t0
    assert res.status == "parse_error"
    assert res.error == "worker error: ValueError"
    assert "attacker" not in res.error
    assert res.findings == []
    assert res.anomalies == []
    assert elapsed < 10
