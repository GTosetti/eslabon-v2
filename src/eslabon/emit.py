"""Build ECS-style events and append them to a JSON Lines file."""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from eslabon import __version__
from eslabon.catalog import Rule
from eslabon.model import Finding, PackageRef, ScanResult
from eslabon.sanitize import clean_text

# Latest ECS release seen on github.com/elastic/ecs/releases (docs/event-schema.md).
ECS_VERSION = "9.5.0"
SCHEMA_VERSION = "1.0"
ATTACK_VERSION = "19.2"
MAX_LINE_BYTES = 65_536
_PATH_CAP = 512
_HEX_CAP = 1024


def _timestamp(now: datetime) -> str:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    utc = now.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _hex(raw: str) -> str:
    return raw[:_HEX_CAP]  # _HEX_CAP is even, so the result stays even-length


def _envelope(
    pkg: PackageRef, scan_id: str, now: datetime, kind: str, dataset: str
) -> dict:
    ev: dict = {
        "@timestamp": _timestamp(now),
        "ecs": {"version": ECS_VERSION},
        "event": {"kind": kind, "module": "eslabon", "dataset": dataset},
        "package": {
            "name": clean_text(pkg.name, _PATH_CAP) if pkg.name else "unknown",
            "version": clean_text(pkg.version, _PATH_CAP) if pkg.version else "",
        },
    }
    if pkg.archive_sha256:
        ev["file"] = {"hash": {"sha256": pkg.archive_sha256}}
    ev["eslabon"] = {
        "schema_version": SCHEMA_VERSION,
        "attack_version": ATTACK_VERSION,
        "ecosystem": pkg.ecosystem,
        "scan_id": scan_id,
    }
    return ev


def finding_event(
    f: Finding, rule: Rule, pkg: PackageRef, scan_id: str, now: datetime
) -> dict:
    ev = _envelope(pkg, scan_id, now, "alert", "eslabon.finding")
    ev["event"].update(
        category=["package", "malware"], type=["info"], severity=rule.severity
    )
    ev["rule"] = {
        "id": rule.id, "name": rule.name, "ruleset": "eslabon", "version": __version__,
    }
    ev["threat"] = {
        "framework": "MITRE ATT&CK",
        "technique": {"id": list(rule.techniques), "name": list(rule.technique_names)},
        "tactic": {"id": list(rule.tactics), "name": list(rule.tactic_names)},
    }
    ev["eslabon"]["evidence"] = {
        "file": clean_text(f.file, _PATH_CAP),
        "line": f.line,
        "snippet": clean_text(f.snippet, 1024),
        "name_hex": _hex(f.name_hex),
        "match_count": f.match_count,
    }
    ev["eslabon"]["mitigation"] = {
        "action": rule.action, "residual_gap": rule.residual_gap, "detect": rule.detect,
    }
    return ev


def summary_event(r: ScanResult, pkg: PackageRef, scan_id: str, now: datetime) -> dict:
    ev = _envelope(pkg, scan_id, now, "event", "eslabon.scan")
    ev["event"]["outcome"] = "success" if r.status == "ok" else "failure"
    scan: dict = {
        "status": r.status,
        "files_scanned": r.files_scanned,
        "bytes_read": r.bytes_read,
        "findings": len(r.findings),
        "anomalies": len(r.anomalies),
        "anomaly_kinds": sorted({a.kind for a in r.anomalies}),
        "osv_status": r.osv_status,
        "duration_ms": r.duration_ms,
    }
    if r.error is not None:
        scan["error"] = clean_text(r.error, _PATH_CAP)
    ev["eslabon"]["scan"] = scan
    if r.identity_source is not None:
        ev["eslabon"]["identity_source"] = r.identity_source
    return ev


def write_events(events: Iterable[dict], out: Path) -> int:
    """Append one JSON line per event to `out`; return the number of lines."""
    lines = []
    for ev in events:
        line = json.dumps(ev, ensure_ascii=True, separators=(",", ":"))
        if len(line.encode("ascii")) >= MAX_LINE_BYTES:
            raise ValueError("event line exceeds 64 KB")
        lines.append(line)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8", newline="\n") as fh:
        for line in lines:
            fh.write(line + "\n")
    return len(lines)
