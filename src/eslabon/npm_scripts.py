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
# node -e / -p token rule. NO shell emulation: separators, quoting and
# escapes are not interpreted, because every emulation (separators, quotes,
# CR, cmd.exe carets, bash $'...') was one more way to hide a node -e. A node
# binary word (node, nodejs, optionally .exe/.cmd, optionally behind a / or \
# path, a quote, '(', '$' or '`') followed ANYWHERE later in the script by an
# eval flag word (-e, -p, -pe, -ep, --eval, --print, --eval=..., --print=...)
# fires, even when the flag belongs to a later command (accepted over-firing:
# 'node install.js && echo -e done'). Words are delimited by whitespace, the
# start/end, quotes, parens, backticks and ; & |, so node-gyp, ts-node,
# nodemon, -env, -ep2 and --evaluate are not words of the rule.
# Case-insensitive (NODE.EXE -E fires).
_NODE_WORD = r"""(?<![^\s;&|"'`()$/\\])node(?:js)?(?:\.exe|\.cmd)?(?![^\s;&|"'`()])"""
_FLAG_END = r"""(?![^\s;&|"'`()])"""
_EVAL_FLAG = (
    r"""(?<![^\s;&|"'`(])(?:(?:-e|-p|-pe|-ep)""" + _FLAG_END
    + r"|--(?:eval|print)(?:=|" + _FLAG_END + "))"
)
# One left-to-right pass; each branch starts with a fixed character and its
# lookarounds are O(1), so the scan is linear whatever the input.
_NODE_TOKEN = re.compile(
    "(?P<node>" + _NODE_WORD + ")|(?P<flag>" + _EVAL_FLAG + ")", re.IGNORECASE
)


def node_evals(script: str) -> int:
    """node words in ``script`` that are followed later by an eval flag.

    Pairs are taken left to right without overlap: a flag closes the open
    node word, so ``node -e 1; node -e 2`` counts 2 and ``node a node b -e``
    counts 1.
    """
    if "node" not in script.lower():  # fast path for the common script
        return 0
    count, open_node = 0, False
    for m in _NODE_TOKEN.finditer(script):
        if m.lastgroup == "node":
            open_node = True
        elif open_node:
            count += 1
            open_node = False
    return count


@functools.cache
def _script_rules() -> yara.Rules:
    """The esl002 namespace, compiled once per process (worker included)."""
    return yara_engine.compile_script_rules()


def _is_top_package_json(m: Member) -> bool:
    readings = path_readings(m.stored_path)
    return any(_TOP_PACKAGE_JSON.fullmatch(r) for r in readings)


def _text(data: bytes) -> str:
    """npm's view of the bytes: String(buffer) (UTF-8, U+FFFD for invalid
    sequences, never fails), then stripBOM (ONE leading U+FEFF)."""
    text = data.decode("utf-8", errors="replace")
    return text[1:] if text.startswith(chr(0xFEFF)) else text


def _reject_constant(name: str) -> int:
    """NaN, Infinity and -Infinity: Python accepts them, JSON.parse does not."""
    raise ValueError(f"{name} is not JSON")


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
        doc = json.loads(_text(data), parse_int=len, parse_constant=_reject_constant)
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


_JSON_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[{}\[\]]')
_SCRIPTS_OPEN = re.compile(r"\s*:\s*\{")


def _scripts_span(text: str) -> tuple[int, int] | None:
    """Offsets of the top-level ``"scripts"`` object ({ .. }) in the raw text,
    or None. Walks only strings and brackets, so braces inside strings or the
    nested ``"config"`` object do not count."""
    depth, pending, begin = 0, False, -1
    last = None  # JSON.parse keeps the LAST duplicate top-level key
    for tok in _JSON_TOKEN.finditer(text):
        t = tok.group()
        if t[0] == '"':
            if depth == 1 and t == '"scripts"':
                pending = _SCRIPTS_OPEN.match(text, tok.end()) is not None
            continue
        if t in "{[":
            depth += 1
            if pending and t == "{":
                begin, pending = tok.start(), False
        else:
            depth -= 1
            if begin >= 0 and depth == 1 and t == "}":
                last, begin = (begin, tok.end()), -1
    return last


def _key_line(text: str, key: str, span: tuple[int, int] | None) -> int:
    """1-based line of the ``"key":`` inside the top-level ``"scripts"`` object
    (the one npm runs), given its ``span`` from _scripts_span. If that object
    cannot be located, the last ``"key":`` anywhere, or 1 if it is not found
    verbatim (e.g. written with escapes)."""
    lo, hi = span if span else (0, len(text))
    start = -1
    for hit in re.finditer(r'"' + key + r'"\s{0,100}:', text[lo:hi]):
        start = lo + hit.start()
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
    raw = m.stored_path
    doc, problem = load_package_json(m.data)
    if doc is None:
        ctx.anomalies.append(package_json_anomaly(problem, raw))
        return []
    scripts = doc.get("scripts")
    if not isinstance(scripts, dict):
        return []

    total, first = 0, None  # first = (line, script) of the earliest matching key
    text = _text(m.data)
    span: tuple[int, int] | None | bool = False  # walked on the first match only
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
        if span is False:
            span = _scripts_span(text)
        line = _key_line(text, key, span)
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
