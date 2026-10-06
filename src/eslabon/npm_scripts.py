"""ESL-002 npm-install-script-exec: judge the lifecycle scripts npm runs.

Applies to the top-level ``package.json`` of an npm archive: any member whose
stored name, under ANY reading (``archive.path_readings``), is
``<one dir>/package.json`` -- node-tar strips that first component. Erring on
the side of scanning more, a rewritten or odd name is checked too, and every
candidate gets its own finding.

The file is parsed with ``json`` (last duplicate key wins, as with JSON.parse)
and only ``scripts.preinstall``, ``scripts.install`` and ``scripts.postinstall``
are matched, each as its own byte string, against the separately compiled
``esl002`` namespace. A URL elsewhere in the file never fires. Nothing is ever
executed; script text only reaches the output through ``clean_text``.
"""

from __future__ import annotations

import functools
import json
import re

import yara

from eslabon import yara_engine
from eslabon.archive import path_readings
from eslabon.model import (
    Anomaly,
    Finding,
    LimitsExceeded,
    Member,
    ParseError,
    ScanContext,
)
from eslabon.sanitize import clean_text, to_hex

LIFECYCLE = ("preinstall", "install", "postinstall")
_TOP_PACKAGE_JSON = re.compile(r"[^/]+/package\.json")
# core-js and friends: `node -e "try{require('./postinstall')}catch(e){}"`.
# Evaluating only a require() of a local file is `node file.js`, the shape
# ESL-002 deliberately leaves to ESL-003/ESL-004 (design.md, residual gaps).
# The path class has no ':' or quotes, so the script cannot carry anything else.
_LOCAL_REQUIRE = re.compile(
    r"""node\s{1,10}(?:-e|--eval)\s{1,10}(["'])\s*(?:try\s*\{\s*)?"""
    r"""require\(\s*(["'])\.{1,2}/[\w./-]{1,200}\2\s*\)\s*;?\s*"""
    r"""(?:\}\s*catch\s*(?:\(\s*\w*\s*\))?\s*\{\s*\}\s*)?\1"""
)
_BAD_JSON = "package.json is not a UTF-8 JSON object; scripts not checked"


@functools.cache
def _script_rules() -> yara.Rules:
    """The esl002 namespace, compiled once per process (worker included)."""
    return yara_engine.compile_script_rules()


def _is_top_package_json(m: Member) -> bool:
    readings = path_readings(m.raw_path or m.path)
    return any(_TOP_PACKAGE_JSON.fullmatch(r) for r in readings)


def _parse(data: bytes) -> dict | None:
    """The JSON object, or None if npm could not read it either.

    Integers are not converted: Python refuses int strings over 4300 digits
    where JSON.parse accepts them, which would hide the scripts.
    """
    try:
        text = data.decode("utf-8-sig")
        doc = json.loads(text, parse_int=len, parse_constant=len)
    except (ValueError, RecursionError):  # UnicodeDecodeError is a ValueError
        return None
    return doc if isinstance(doc, dict) else None


def _key_line(text: str, key: str) -> int:
    """1-based line of the last ``"key":`` in the raw text (the one JSON.parse
    keeps), or 1 if it is not found verbatim (e.g. written with escapes)."""
    start = -1
    for hit in re.finditer(r'"' + key + r'"\s{0,100}:', text):
        start = hit.start()
    return text.count("\n", 0, start) + 1 if start >= 0 else 1


def _count(script: str, ctx: ScanContext) -> int:
    data = script.encode("utf-8", errors="surrogatepass")
    try:
        matches = _script_rules().match(
            data=data,
            timeout=ctx.limits.yara_timeout_s,
            warnings_callback=lambda *_: yara.CALLBACK_CONTINUE,
        )
    except yara.TimeoutError as exc:
        raise LimitsExceeded(
            f"yara timeout after {ctx.limits.yara_timeout_s}s on package.json scripts"
        ) from exc
    except yara.Error as exc:
        raise ParseError(f"yara error: {type(exc).__name__}") from exc
    # $enc_* are helper flags of the PowerShell condition, not matches of their own
    return sum(
        len(s.instances)
        for match in matches
        for s in match.strings
        if not s.identifier.startswith("$enc_")
    )


def scan_package_json(m: Member, ctx: ScanContext) -> list[Finding]:
    """One ESL-002 Finding per top-level package.json whose lifecycle scripts
    match; a malformed one records the ``bad_package_json`` anomaly."""
    if ctx.archive_kind != "npm" or not _is_top_package_json(m):
        return []
    raw = m.raw_path or m.path
    doc = _parse(m.data)
    if doc is None:
        ctx.anomalies.append(Anomaly("bad_package_json", to_hex(raw), _BAD_JSON))
        return []
    scripts = doc.get("scripts")
    if not isinstance(scripts, dict):
        return []

    total, first = 0, None  # first = (line, script) of the earliest matching key
    text = m.data.decode("utf-8-sig")  # decodes: _parse succeeded on it
    for key in LIFECYCLE:
        script = scripts.get(key)
        if not isinstance(script, str) or _LOCAL_REQUIRE.fullmatch(script):
            continue
        count = _count(script, ctx)
        if not count:
            continue
        total += count
        line = _key_line(text, key)
        if first is None or line < first[0]:
            first = (line, script)
    if first is None:
        return []
    return [
        Finding(
            rule_id="ESL-002",
            file=m.path,
            member_index=m.index,
            line=first[0],
            snippet=clean_text(first[1].encode("utf-8", errors="surrogatepass")),
            match_count=total,
            name_hex=to_hex(raw),
        )
    ]
