"""Measure ESL-005 by name only (no download, no network).

Usage: ``python scripts/measure_typosquat.py [--list-fp] [POSITIVES.json ...]``

- False positives: every name ranked 5,001-6,000 in each bundled top list is
  checked; these are popular, legitimate packages just outside the exemption.
- Recall: each POSITIVES file is ``{"pypi": [[name, id], ...], "npm": [...]}``
  (e.g. known-malicious typosquat names with their OSV MAL- ids). A small
  built-in set of historical squats is always measured too.

Uses the real ``eslabon.typosquat.check`` against the bundled lists.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from eslabon import typosquat

ECOSYSTEMS = ("pypi", "npm")
HISTORICAL = {
    "pypi": [
        "reqeusts", "colourama", "urlib3", "djanga", "setup-tools", "python3-dateutil",
    ],
    "npm": [
        "@typescript_eslinter/eslint", "jquerry", "crossenv", "mongose", "babelcli",
        "electorn", "discordi.js", "loadyaml",
    ],
}


def measure(positive_files: list[Path], list_fp: bool) -> list[str]:
    positives = [json.loads(p.read_text("utf-8")) for p in positive_files]
    header = ["ecosystem", "FP ranks 5001-6000"]
    header += [f"recall {p.stem}" for p in positive_files] + ["recall historical"]
    rows = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    details: list[str] = []
    for eco in ECOSYSTEMS:
        top = typosquat.load_top_list(eco)
        sample = typosquat.bundled_top_document(eco)["names"][5000:6000]
        fps = [f.snippet for n in sample if (f := typosquat.check(n, eco, top))]
        cells = [eco, f"{len(fps)}/{len(sample)}"]
        for pos in positives:
            names = [entry[0] for entry in pos.get(eco, [])]
            hit = sum(1 for n in names if typosquat.check(n, eco, top))
            cells.append(f"{hit}/{len(names)}")
        hist = HISTORICAL[eco]
        hist_hit = sum(1 for n in hist if typosquat.check(n, eco, top))
        cells.append(f"{hist_hit}/{len(hist)}")
        rows.append("| " + " | ".join(cells) + " |")
        if list_fp:
            details.append(f"{eco} false positives: " + "; ".join(fps))
    return rows + details


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("positives", nargs="*", type=Path)
    parser.add_argument("--list-fp", action="store_true")
    args = parser.parse_args(argv)
    for line in measure(args.positives, args.list_fp):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
