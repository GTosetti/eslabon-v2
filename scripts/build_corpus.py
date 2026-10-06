"""Generate corpus/legit.toml: the top 100 PyPI and top 100 npm packages, pinned.

Usage: ``python scripts/build_corpus.py [--count N] [--out corpus/legit.toml]``

Reads the bundled top lists (``src/eslabon/data/top_{pypi,npm}.json``) and, for
each of the first N names, asks the registry for its LATEST version:

- PyPI: ``https://pypi.org/pypi/<name>/json`` -> ``info.version``.
- npm: ``https://registry.npmjs.org/<name>/latest`` (the registry resolves the
  ``dist-tags.latest`` tag) -> ``version``.

Then it resolves that exact version with ``eslabon.fetch.resolve`` (the same
code ``eslabon scan name==version`` uses) to check that a downloadable artifact
exists. Only registry JSON metadata is read: no archive is downloaded, nothing
is installed or executed. Names without an artifact are skipped and recorded
in the file header. All network access goes through eslabon.fetch (https to
the registry hosts only, size cap, deadline).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from urllib.parse import quote

from eslabon import fetch
from eslabon.model import FetchError

ECOSYSTEMS = ("pypi", "npm")
ROOT = Path(__file__).resolve().parent.parent


def bundled_list(ecosystem: str) -> dict:
    raw = files("eslabon").joinpath("data", f"top_{ecosystem}.json").read_bytes()
    return json.loads(raw)


def latest_version(name: str, ecosystem: str) -> str:
    deadline = fetch.new_deadline()
    if ecosystem == "npm":
        doc = fetch._get_json(fetch.npm_url(name, "latest"), None, deadline)
        version = doc.get("version")
    else:
        url = f"{fetch.PYPI_API}/{quote(name, safe='')}/json"
        doc = fetch._get_json(url, None, deadline)
        info = doc.get("info")
        version = info.get("version") if isinstance(info, dict) else None
    if not isinstance(version, str) or not version:
        raise FetchError("no latest version in registry metadata")
    return version


def _toml_str(text: str) -> str:
    return json.dumps(text, ensure_ascii=True)  # a JSON string is a TOML basic string


def build(count: int) -> tuple[str, list[str]]:
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    entries: list[tuple[str, str, str]] = []
    skipped: list[str] = []
    sources: list[str] = []
    for eco in ECOSYSTEMS:
        top = bundled_list(eco)
        sources.append(f"# {eco}: {top['source']} (retrieved {top['retrieved']})")
        for name in top["names"][:count]:
            try:
                version = latest_version(name, eco)
                fetch.resolve(name, version, eco)
            except FetchError as exc:
                skipped.append(f"{eco} {name}: {exc}")
                print(f"skip {eco} {name}: {exc}", file=sys.stderr)
                continue
            entries.append((eco, name, version))
            print(f"{eco} {name}=={version}", file=sys.stderr)
    lines = [
        "# Legitimate corpus for the false-positive measurement"
        " (scripts/measure_fp.py).",
        f"# Generated {now} by scripts/build_corpus.py: the top {count} names of each",
        "# bundled top list, each pinned to its latest registry version at that time.",
        *sources,
        "# Skipped (no downloadable artifact or no latest version):",
        *([f"#   {s}" for s in skipped] or ["#   none"]),
        "",
    ]
    for eco, name, version in entries:
        lines += [
            "[[package]]",
            f"ecosystem = {_toml_str(eco)}",
            f"name = {_toml_str(name)}",
            f"version = {_toml_str(version)}",
            "",
        ]
    return "\n".join(lines), skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--out", type=Path, default=ROOT / "corpus" / "legit.toml")
    args = parser.parse_args(argv)
    text, skipped = build(args.count)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(text.encode("ascii"))
    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    print(f"wrote {args.out} sha256={digest} skipped={len(skipped)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
