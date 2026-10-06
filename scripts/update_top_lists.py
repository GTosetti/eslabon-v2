"""Refresh the bundled top-package lists used by ESL-005 (typosquat).

Usage: ``python scripts/update_top_lists.py``

Downloads two public ranked LISTS of package names (never a package) and writes
``src/eslabon/data/top_pypi.json`` and ``src/eslabon/data/top_npm.json`` as
``{"source": url, "retrieved": "YYYY-MM-DD", "names": [top 6000 in rank order]}``.
``retrieved`` is the UTC date of the download.

Sources:
- PyPI: hugovk/top-pypi-packages, ``{"rows": [{"project", "download_count"}]}``,
  30-day downloads, most downloaded first.
- npm: wooorm/npm-high-impact ``lib/top-download.js``: one
  ``export const topDownload = [...]`` array of quoted names ranked by downloads
  only. It is a JS module, so it is parsed as text with a strict line-by-line
  pattern; it is never evaluated.

Poisoning guard: a list is refused if it lacks well-known anchor names, or if
more than half of the previously shipped top 1,000 is gone from the new one.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
NPM_URL = (
    "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top-download.js"
)
NPM_ARRAY = "topDownload"
KEEP = 6000
TIMEOUT_S = 30
MAX_BYTES = 16 * 2**20
MAX_NAME = 214
TOP = 1000
MAX_CHANGE = 0.5  # fraction of the previous top 1,000 allowed to disappear
ANCHORS = {
    "pypi": ("requests", "numpy", "boto3", "setuptools"),
    "npm": ("react", "lodash", "typescript", "express"),
}
OUT_DIR = Path(__file__).resolve().parent.parent / "src" / "eslabon" / "data"

_PYPI_NAME = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?")
_NPM_NAME = re.compile(r"(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+")
_NPM_LINE = re.compile(r"\s*'([^'\\]*)',?\s*")


def fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("refusing a non-https URL")
    req = urllib.request.Request(url, headers={"User-Agent": "eslabon-top-lists"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:  # noqa: S310
        final = resp.geturl()
        if not final.startswith("https://"):
            raise ValueError(f"redirected away from https: {final[:200]}")
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
    if len(lines) < 2 or lines[0].strip() != f"export const {NPM_ARRAY} = [":
        raise ValueError("unexpected npm list layout")
    if lines[-1].strip() != "]":
        raise ValueError("unexpected npm list layout")
    names = []
    for line in lines[1:-1]:
        m = _NPM_LINE.fullmatch(line)
        if not m:
            raise ValueError(f"unexpected npm list line: {line[:80]!r}")
        names.append(m.group(1))
    return _checked(names, _NPM_NAME)


def sanity_check(ecosystem: str, names: list[str], previous: list[str] | None) -> None:
    """Refuse a list that looks poisoned or broken (see module docstring)."""
    missing = [a for a in ANCHORS[ecosystem] if a not in names[:TOP]]
    if missing:
        raise ValueError(f"{ecosystem}: anchor names missing from top {TOP}: {missing}")
    if previous:
        old = previous[:TOP]
        gone = len(set(old) - set(names[:TOP]))
        if gone > MAX_CHANGE * len(old):
            raise ValueError(
                f"{ecosystem}: {gone} of the previous top 1,000 are gone; refusing"
            )


def _previous(path: Path) -> list[str] | None:
    if not path.is_file():
        return None
    return json.loads(path.read_text("ascii"))["names"]


def write(path: Path, source: str, names: list[str], today: str) -> None:
    doc = {"source": source, "retrieved": today, "names": names}
    path.write_text(json.dumps(doc, indent=0, ensure_ascii=True) + "\n", "ascii")


def main() -> int:
    today = datetime.now(UTC).strftime("%Y-%m-%d")  # UTC date, by design
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pypi = parse_pypi(fetch(PYPI_URL))
    npm = parse_npm(fetch(NPM_URL))
    pypi_path, npm_path = OUT_DIR / "top_pypi.json", OUT_DIR / "top_npm.json"
    sanity_check("pypi", pypi, _previous(pypi_path))
    sanity_check("npm", npm, _previous(npm_path))
    write(pypi_path, PYPI_URL, pypi, today)
    write(npm_path, NPM_URL, npm, today)
    print(f"pypi: {len(pypi)} names (first {pypi[0]}), npm: {len(npm)} names "
          f"(first {npm[0]}), retrieved {today}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
