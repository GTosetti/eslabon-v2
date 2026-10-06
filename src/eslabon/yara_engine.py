"""YARA engine: compile the bundled rules once and scan one member at a time.

Every rule file in ``eslabon/rules/*.yar`` gets its own namespace (the file
stem) and every rule carries ``meta: esl_id``. Matches are reported as one
``Finding`` per (esl_id, member). Member bytes are attacker-controlled: they
are only matched against, never decoded beyond the sanitised snippet.
"""

from __future__ import annotations

from importlib import resources

import yara

from eslabon.model import Finding, LimitsExceeded, Member, ParseError, ScanContext
from eslabon.sanitize import clean_text, to_hex

_BEFORE = 120  # snippet context before the first match
_AFTER = 200  # and after it


def _leading_space(matched: bytes) -> int:
    """Bytes of whitespace a match starts with (e.g. a prefix byte that is a
    line break): the finding points at the first byte after them, so ``line``
    is the line of the evaluator, not of the preceding break."""
    return len(matched) - len(matched.lstrip())


def compile_rules() -> yara.Rules:
    """Compile every bundled ``rules/*.yar``; a YARA warning is an error."""
    root = resources.files("eslabon").joinpath("rules")
    with resources.as_file(root) as rule_dir:
        paths = {p.stem: str(p) for p in sorted(rule_dir.glob("*.yar"))}
        if not paths:
            raise RuntimeError("no YARA rules bundled")
        return yara.compile(filepaths=paths, error_on_warning=True)


def scan_member(m: Member, ctx: ScanContext) -> list[Finding]:
    """One Finding per matched esl_id: lowest offset, total instance count."""
    if ctx.rules is None or not m.data:
        return []
    try:
        matches = ctx.rules.match(data=m.data, timeout=ctx.limits.yara_timeout_s)
    except yara.TimeoutError as exc:
        raise LimitsExceeded(
            f"yara timeout after {ctx.limits.yara_timeout_s}s on member {m.index}"
        ) from exc
    except yara.Error as exc:
        raise ParseError(f"yara error: {type(exc).__name__}") from exc

    merged: dict[str, tuple[int, int]] = {}  # esl_id -> (first offset, count)
    for match in matches:
        esl_id = match.meta["esl_id"]
        for s in match.strings:
            for inst in s.instances:
                off = inst.offset + _leading_space(inst.matched_data)
                first, count = merged.get(esl_id, (off, 0))
                merged[esl_id] = (min(first, off), count + 1)

    data = m.data
    name_hex = to_hex(m.raw_path or m.path)
    out: list[Finding] = []
    for esl_id, (off, count) in sorted(merged.items()):
        out.append(
            Finding(
                rule_id=esl_id,
                file=m.path,
                member_index=m.index,
                line=data.count(b"\n", 0, off) + 1,
                snippet=clean_text(data[max(0, off - _BEFORE) : off + _AFTER]),
                match_count=count,
                name_hex=name_hex,
            )
        )
    return out
