"""Refresh the bundled top-package lists used by ESL-005 (typosquat).

Usage: ``python scripts/update_top_lists.py``

Downloads two public ranked LISTS of package names (never a package) and writes
``src/eslabon/data/top_pypi.json`` and ``src/eslabon/data/top_npm.json`` as
``{"source": url, "retrieved": "YYYY-MM-DD", "names": [top 6000 in rank order]}``.

Sources:
- PyPI: hugovk/top-pypi-packages, ``{"rows": [{"project", "download_count"}]}``,
  30-day downloads from the PyPI BigQuery/ClickHouse data, most downloaded first.
- npm: wooorm/npm-high-impact ``lib/top.js``: one ``export const top = [...]``
  array of quoted names, most downloaded first, then packages ranked by number
  of dependents. It is a JS module, so it is parsed as text with a strict
  line-by-line pattern; it is never evaluated.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
NPM_URL = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js"
KEEP = 6000
TIMEOUT_S = 30
MAX_BYTES = 16 * 2**20
MAX_NAME = 214
OUT_DIR = Path(__file__).resolve().parent.parent / "src" / "eslabon" / "data"

_PYPI_NAME = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?")
_NPM_NAME = re.compile(r"(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+")
_NPM_LINE = re.compile(r"\s*'([^'\\]*)',?\s*")


def fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("refusing a non-https URL")
    req = urllib.request.Request(url, headers={"User-Agent": "eslabon-top-lists"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:  # noqa: S310
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{url}: response larger than {MAX_BYTES} bytes")
    return data


def _checked(names: list[str], pattern: re.Pattern[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for name in names:
        if len(name) > MAX_NAME or not pattern.fullmatch(name):
            raise ValueError(f"unexpected package name: {name[:80]!r}")
        if name not in seen:
            seen.add(name)
            out.append(name)
    if len(out) < KEEP:
        raise ValueError(f"list too short: {len(out)} < {KEEP}")
    return out[:KEEP]


def parse_pypi(data: bytes) -> list[str]:
    doc = json.loads(data.decode("utf-8"))
    rows = doc["rows"]
    if not isinstance(rows, list):
        raise ValueError("rows is not a list")
    for row in rows:
        if not isinstance(row.get("project"), str):
            raise ValueError("row without a project name")
        if not isinstance(row.get("download_count"), int):
            raise ValueError("row without a download count")
    rows = sorted(rows, key=lambda r: -r["download_count"])  # stable: keeps ties
    return _checked([r["project"] for r in rows], _PYPI_NAME)


def parse_npm(data: bytes) -> list[str]:
    lines = data.decode("utf-8").splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    if len(lines) < 2 or lines[0].strip() != "export const top = [":
        raise ValueError("unexpected top.js layout")
    if lines[-1].strip() != "]":
        raise ValueError("unexpected top.js layout")
    names = []
    for line in lines[1:-1]:
        m = _NPM_LINE.fullmatch(line)
        if not m:
            raise ValueError(f"unexpected top.js line: {line[:80]!r}")
        names.append(m.group(1))
    return _checked(names, _NPM_NAME)


def write(path: Path, source: str, names: list[str], today: str) -> None:
    doc = {"source": source, "retrieved": today, "names": names}
    path.write_text(json.dumps(doc, indent=0, ensure_ascii=True) + "\n", "ascii")


def main() -> int:
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pypi = parse_pypi(fetch(PYPI_URL))
    npm = parse_npm(fetch(NPM_URL))
    write(OUT_DIR / "top_pypi.json", PYPI_URL, pypi, today)
    write(OUT_DIR / "top_npm.json", NPM_URL, npm, today)
    print(f"pypi: {len(pypi)} names (first {pypi[0]}), npm: {len(npm)} names "
          f"(first {npm[0]}), retrieved {today}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
