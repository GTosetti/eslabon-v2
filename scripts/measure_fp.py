"""Measure false positives on the legitimate corpus (corpus/legit.toml).

Usage::

    python scripts/measure_fp.py [--corpus corpus/legit.toml] [--work DIR]
                                 [--timeout 300] [--only ECO:NAME ...]
                                 [--package ECO:NAME==VERSION ...]
                                 [--aggregate DIR/results.json]

Each package is scanned with our own CLI, ``python -m eslabon scan
name==version --ecosystem ECO --out DIR/NNN.jsonl``, in a subprocess, one at a
time (sequential, to be polite to the registries), with a wall-clock timeout.
OSV is NOT skipped: an ESL-006 finding on a legitimate latest version counts.
These are legitimate packages, so this runs on the host (design.md section 9);
nothing is installed or executed, only fetched and statically scanned by
eslabon. The JSONL and ``results.json`` go to a temporary directory outside the
repository (or --work).

The output is a Markdown table per ecosystem and in total: fully scanned (status
ok), incomplete (any other status, listed by name with status and reason), and
packages with at least one finding (every finding on a legitimate package is a
false positive), by rule, followed by the evidence of each finding.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import tomllib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ECOSYSTEMS = ("pypi", "npm")


def load_corpus(path: Path) -> list[dict]:
    with path.open("rb") as fh:
        return list(tomllib.load(fh)["package"])


def _parse_events(path: Path) -> tuple[dict | None, list[dict]]:
    summary, findings = None, []
    if not path.exists():
        return None, []
    for line in path.read_text("utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        if ev["event"]["dataset"] == "eslabon.scan":
            summary = ev
        else:
            ev_info = ev["eslabon"]["evidence"]
            findings.append(
                {
                    "rule": ev["rule"]["id"],
                    "file": ev_info.get("file"),
                    "line": ev_info.get("line"),
                    "match_count": ev_info.get("match_count"),
                    "snippet": ev_info.get("snippet"),
                }
            )
    return summary, findings


def scan_one(pkg: dict, out: Path, timeout: float) -> dict:
    target = f"{pkg['name']}=={pkg['version']}"
    cmd = [
        sys.executable, "-m", "eslabon", "scan", target,
        "--ecosystem", pkg["ecosystem"], "--out", str(out),
    ]
    record = dict(pkg)
    start = time.monotonic()
    try:
        proc = subprocess.run(  # fixed argv, no shell
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        record["exit_code"] = proc.returncode
        record["stderr"] = proc.stderr.strip()[-500:]
    except subprocess.TimeoutExpired:
        record["exit_code"] = None
        record["stderr"] = f"harness timeout after {timeout} s"
    record["wall_s"] = round(time.monotonic() - start, 1)
    summary, findings = _parse_events(out)
    record["findings"] = findings
    if summary is None:
        record.update(status="no_summary", error=record["stderr"], anomaly_kinds=[])
        return record
    scan = summary["eslabon"]["scan"]
    record.update(
        status=scan["status"],
        error=scan.get("error"),
        anomaly_kinds=scan["anomaly_kinds"],
        osv_status=scan["osv_status"],
        files_scanned=scan["files_scanned"],
        bytes_read=scan["bytes_read"],
        duration_ms=scan["duration_ms"],
    )
    return record


def _row(label: str, recs: list[dict]) -> str:
    full = [r for r in recs if r["status"] == "ok"]
    incomplete = [r for r in recs if r["status"] != "ok"]
    fp = [r for r in recs if r["findings"]]
    by_rule = Counter(rule for r in fp for rule in {f["rule"] for f in r["findings"]})
    rules = ", ".join(f"{k}: {v}" for k, v in sorted(by_rule.items())) or "-"
    fp_full = sum(1 for r in full if r["findings"])
    return (
        f"| {label} | {len(recs)} | {len(full)} | {len(incomplete)} | "
        f"{len(fp)} ({fp_full} of them fully scanned) | {rules} |"
    )


def report(records: list[dict]) -> str:
    out = [
        "| ecosystem | packages | fully scanned | incomplete "
        "| packages with >=1 FP | FP packages by rule |",
        "|---|---|---|---|---|---|",
    ]
    for eco in ECOSYSTEMS:
        recs = [r for r in records if r["ecosystem"] == eco]
        if recs:
            out.append(_row(eco, recs))
    out.append(_row("total", records))
    out += ["", "Incomplete scans:", ""]
    bad = [r for r in records if r["status"] != "ok"]
    for r in bad:
        reason = r.get("error") or ""
        kinds = ",".join(r.get("anomaly_kinds") or [])
        out.append(
            f"- {r['ecosystem']} {r['name']}=={r['version']}: {r['status']}"
            f" ({reason}) anomalies=[{kinds}]"
        )
    if not bad:
        out.append("- none")
    out += ["", "False positives (evidence):", ""]
    fps = [r for r in records if r["findings"]]
    for r in fps:
        for f in r["findings"]:
            snippet = (f["snippet"] or "").replace("\n", "\\n")[:300]
            out.append(
                f"- {r['ecosystem']} {r['name']}=={r['version']} {f['rule']} "
                f"{f['file']}:{f['line']} x{f['match_count']}: `{snippet}`"
            )
    if not fps:
        out.append("- none")
    walls = sorted(r["wall_s"] for r in records)
    if walls:
        out += [
            "",
            f"Wall time: total {sum(walls):.0f} s, median {walls[len(walls) // 2]} s, "
            f"max {walls[-1]} s.",
        ]
    anomalies = Counter(k for r in records for k in r.get("anomaly_kinds") or [])
    out.append(f"Anomaly kinds (packages): {dict(sorted(anomalies.items()))}")
    return "\n".join(out)


def _select(corpus: list[dict], only: list[str], extra: list[str]) -> list[dict]:
    chosen = corpus
    if only:
        wanted = {tuple(o.split(":", 1)) for o in only}
        chosen = [p for p in corpus if (p["ecosystem"], p["name"]) in wanted]
    for spec in extra:
        eco, target = spec.split(":", 1)
        name, version = target.split("==", 1)
        chosen.append({"ecosystem": eco, "name": name, "version": version})
    return chosen


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, default=ROOT / "corpus" / "legit.toml")
    parser.add_argument("--work", type=Path)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--only", action="append", default=[])
    parser.add_argument("--package", action="append", default=[])
    parser.add_argument("--aggregate", type=Path)
    args = parser.parse_args(argv)
    if args.aggregate:
        records = json.loads(args.aggregate.read_text("utf-8"))
        print(report(records))
        return 0
    corpus = [] if args.package and not args.only else load_corpus(args.corpus)
    packages = _select(corpus, args.only, args.package)
    work = args.work or Path(tempfile.mkdtemp(prefix="eslabon-fp-"))
    work = work.resolve()
    if work == ROOT or ROOT in work.parents:
        parser.error("--work must be outside the repository")
    work.mkdir(parents=True, exist_ok=True)
    records = []
    for i, pkg in enumerate(packages):
        out = work / f"{i:03d}-{pkg['ecosystem']}.jsonl"
        out.unlink(missing_ok=True)
        rec = scan_one(pkg, out, args.timeout)
        records.append(rec)
        print(
            f"[{i + 1}/{len(packages)}] {pkg['ecosystem']} {pkg['name']}=="
            f"{pkg['version']} exit={rec['exit_code']} status={rec['status']} "
            f"findings={[f['rule'] for f in rec['findings']]} {rec['wall_s']} s",
            file=sys.stderr,
            flush=True,
        )
        (work / "results.json").write_text(json.dumps(records, indent=1), "utf-8")
    print(f"results: {work / 'results.json'}", file=sys.stderr)
    print(report(records))
    return 0


if __name__ == "__main__":
    sys.exit(main())
