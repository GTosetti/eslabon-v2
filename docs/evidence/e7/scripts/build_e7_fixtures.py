"""E7 generate step: write the synthetic fixture archives for the Kali scans.

Usage: <venv>/bin/python build_e7_fixtures.py --repo ~/eslabon --out ~/e7/fixtures
Reuses the builders in scripts/make_logtest_samples.py (tests/builders.py), so
this file holds no string the rules match. Nothing is installed or executed.
"""
import argparse
import hashlib
import sys
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    repo, out = a.repo.resolve(), a.out.resolve()
    if out == repo or repo in out.parents:
        p.error("--out must be outside the repository")
    sys.path.insert(0, str(repo / "scripts"))
    import make_logtest_samples as m

    cases = {
        "esl001/pkg-1.0.tar.gz": m._esl001,
        "esl002/demo-1.0.0.tgz": m._esl002,
        "esl003/demo-0.0.1.tar.gz": m._esl003,
        "esl004/demo-1.0.0.tgz": m._esl004,
        "esl005/reqeusts-1.0.tar.gz": m._esl005,
        "esl006/paypalize-1.0.0.tgz": lambda: m._clean_npm("paypalize"),
        "clean/left-pad-1.0.0.tgz": lambda: m._clean_npm("left-pad"),
        "incomplete/pkg-1.0-py3-none-any.whl": m._encrypted_wheel,
    }
    for rel, build in cases.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        data = build()
        path.write_bytes(data)
        print(hashlib.sha256(data).hexdigest(), rel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
