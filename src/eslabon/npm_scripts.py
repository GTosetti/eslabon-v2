"""ESL-002 npm-install-script-exec: judge the lifecycle scripts npm runs.

Applies to the top-level ``package.json`` of an npm archive: any member whose
stored name, under ANY reading (``archive.path_readings``), is
``<one dir>/package.json`` -- node-tar strips that first component. Erring on
the side of scanning more, a rewritten or odd name is checked too, and every
candidate gets its own finding.

The file is read the way npm reads it (``load_package_json``) and only
``scripts.preinstall``, ``scripts.install`` and ``scripts.postinstall`` are
matched, each as its own byte string with whitespace runs collapsed to one
space, against the separately compiled ``esl002`` namespace. A URL elsewhere
in the file never fires. Nothing is ever executed; script text only reaches
the output through ``clean_text``.
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
BAD_PACKAGE_JSON = "bad_package_json"
PACKAGE_JSON_TOO_DEEP = "package_json_too_deep"
_DETAIL = {
    BAD_PACKAGE_JSON: "package.json is not a JSON object; npm refuses it",
    PACKAGE_JSON_TOO_DEEP: "package.json nests too deep for the parser; not read",
}
_TOP_PACKAGE_JSON = re.compile(r"[^/]+/package\.json")
# core-js and es5-ext: `node -e "try{require('./postinstall')}catch(e){}"`,
# optionally followed by a constant `|| exit 0` / `|| true` (es5-ext).
# Evaluating only a require() of a local file is `node file.js`, the shape
# ESL-002 deliberately leaves to ESL-003/ESL-004 (design.md, residual gaps).
# The path class has no ':' or quotes, so the script cannot carry anything else.
# Matched (fullmatch) on the whitespace-collapsed script.
_LOCAL_REQUIRE = re.compile(
    r"""node\s{1,10}(?:-e|--eval)\s{1,10}(["'])\s*(?:try\s*\{\s*)?"""
    r"""require\(\s*(["'])\.{1,2}/[\w./-]{1,200}\2\s*\)\s*;?\s*"""
    r"""(?:\}\s*catch\s*(?:\(\s*\w*\s*\))?\s*\{\s*\}\s*)?\1"""
    r"""(?:\s*\|\|\s*(?:exit\s+0|true))?"""
)
# node -e / -p token rule (R35). A shell command is the text between two
# separators (; & | or a line break; shell quoting is NOT parsed, so a separator
# inside quotes may only end a command early). In one command, a node binary
# word (node, nodejs, node.exe, nodejs.exe, optionally behind a / or \ path,
# quotes, '(' '$' or '`') followed ANYWHERE later by an eval flag word (-e, -p,
# -pe, -ep, --eval, --print, or --eval=/--print=...) fires. No option list
# to keep complete: values of any shape and number may sit in between.
# Linear: each command is entered once at its start (the lookbehind fails in
# O(1) elsewhere) and both runs are atomic, so nothing is rescanned when a
# command has a node word but no flag. Case-insensitive (NODE.EXE -E fires).
_NODE_WORD = r"""(?<![^\s;&|"'`()$/\\])node(?:js)?(?:\.exe)?(?![^\s;&|"'`()])"""
_EVAL_FLAG = (
    r"""(?<![^\s"'`(])(?:-e|-p|-pe|-ep|--eval|--print)(?:=|(?![^\s;&|"'`)]))"""
)
_IN_COMMAND = r"[^;&|\r\n]"
_NODE_EVAL = re.compile(
    r"(?:^|(?<=[;&|\r\n]))"
    r"(?>(?:(?!" + _NODE_WORD + ")" + _IN_COMMAND + r")*)" + _NODE_WORD
    + r"(?>(?:(?!" + _EVAL_FLAG + ")" + _IN_COMMAND + r")*)" + _EVAL_FLAG,
    re.IGNORECASE,
)


def node_evals(script: str) -> int:
    """Shell commands in ``script`` that run node with inline code (-e/-p)."""
    if "node" not in script.lower():  # fast path: the full pass costs ~1.5 s/10 MiB
        return 0
    return sum(1 for _ in _NODE_EVAL.finditer(script))


@functools.cache
def _script_rules() -> yara.Rules:
    """The esl002 namespace, compiled once per process (worker included)."""
    return yara_engine.compile_script_rules()


def _is_top_package_json(m: Member) -> bool:
    readings = path_readings(m.raw_path or m.path)
    return any(_TOP_PACKAGE_JSON.fullmatch(r) for r in readings)


def _text(data: bytes) -> str:
    """npm's view of the bytes: String(buffer) (UTF-8, U+FFFD for invalid
    sequences, never fails), then stripBOM (ONE leading U+FEFF)."""
    text = data.decode("utf-8", errors="replace")
    return text[1:] if text.startswith(chr(0xFEFF)) else text


def load_package_json(data: bytes) -> tuple[dict | None, str | None]:
    """Parse package.json as npm does: (object, None), or (None, anomaly kind).

    npm reads it with JSON.parse(stripBOM(String(buffer))).
    ``bad_package_json``: a JSON syntax error or a non-object root (npm refuses
    the package). ``package_json_too_deep``: Python's recursive parser gave up
    where V8's iterative one would not, so content went unread. Numbers are
    not converted (Python refuses int strings over 4300 digits; JSON.parse does
    not): each becomes its digit count; strings are untouched. The last
    duplicate key wins, as with JSON.parse.
    """
    try:
        doc = json.loads(_text(data), parse_int=len, parse_constant=len)
    except RecursionError:
        return None, PACKAGE_JSON_TOO_DEEP
    except ValueError:
        return None, BAD_PACKAGE_JSON
    if not isinstance(doc, dict):
        return None, BAD_PACKAGE_JSON
    return doc, None


def package_json_anomaly(kind: str, raw: str) -> Anomaly:
    """The anomaly for a ``load_package_json`` problem on member ``raw``."""
    return Anomaly(kind, to_hex(raw), _DETAIL[kind])


def _key_line(text: str, key: str) -> int:
    """1-based line of the last ``"key":`` in the raw text (the one JSON.parse
    keeps), or 1 if it is not found verbatim (e.g. written with escapes)."""
    start = -1
    for hit in re.finditer(r'"' + key + r'"\s{0,100}:', text):
        start = hit.start()
    return text.count("\n", 0, start) + 1 if start >= 0 else 1


def _count(script: str, ctx: ScanContext) -> int:
    """Rule matches in an already whitespace-collapsed script."""
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
    match; an unreadable one records its ``load_package_json`` anomaly."""
    if ctx.archive_kind != "npm" or not _is_top_package_json(m):
        return []
    raw = m.raw_path or m.path
    doc, problem = load_package_json(m.data)
    if doc is None:
        ctx.anomalies.append(package_json_anomaly(problem or BAD_PACKAGE_JSON, raw))
        return []
    scripts = doc.get("scripts")
    if not isinstance(scripts, dict):
        return []

    total, first = 0, None  # first = (line, script) of the earliest matching key
    text = _text(m.data)
    for key in LIFECYCLE:
        script = scripts.get(key)
        if not isinstance(script, str):
            continue
        # padding must not push a token out of the bounded rule windows
        flat = " ".join(script.split())
        if _LOCAL_REQUIRE.fullmatch(flat):
            continue
        count = _count(flat, ctx) + node_evals(script)
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
