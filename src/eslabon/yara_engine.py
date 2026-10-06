"""YARA engine: compile the bundled rules once and scan one member at a time.

Every rule file in ``eslabon/rules/*.yar`` gets its own namespace (the file
stem) and every rule carries ``meta: esl_id``. Matches are reported as one
``Finding`` per (esl_id, member). Member bytes are attacker-controlled: they
are only matched against, never decoded beyond the sanitised snippet.
"""

from __future__ import annotations

import ipaddress
import re
from importlib import resources

import yara

from eslabon.archive import path_readings
from eslabon.model import Finding, LimitsExceeded, Member, ParseError, ScanContext
from eslabon.sanitize import clean_text, to_hex

_BEFORE = 120  # snippet context before the first match
_AFTER = 200  # and after it
# Namespaces whose matches only count in the setup.py pip runs (ESL-001).
_SETUP_PY_ONLY = frozenset({"esl001"})
# Namespaces matched only against npm lifecycle script strings (ESL-002, in
# npm_scripts): esl002 fires on any URL, so it must never run over a member.
_SCRIPT_ONLY = frozenset({"esl002"})
_SETUP_PY = re.compile(r"(?:[^/]+/)?setup\.py")
# ESL-004: the IP-literal sink only nominates. An instance counts only if the
# address is global; a match whose sinks are all dropped is no finding.
_IP_FILTERED = {"esl004": "$sink_ip"}
_SINK_PREFIX = "$sink"
# YARA stops recording a string after this many instances. A capped IP string
# may hide a public address past the cap, so it is kept unfiltered.
_YARA_MATCH_CAP = 1_000_000
_IPV4 = re.compile(rb"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")
_OCTAL = re.compile(r"0[0-7]*")


def _leading_space(matched: bytes) -> int:
    """Bytes of whitespace a match starts with (e.g. a prefix byte that is a
    line break): the finding points at the first byte after them, so ``line``
    is the line of the evaluator, not of the preceding break."""
    return len(matched) - len(matched.lstrip())


def is_install_setup_py(m: Member, ctx: ScanContext) -> bool:
    """True if ``m`` may be the setup.py pip runs: a PyPI sdist, and ANY
    reading of the stored name (``archive.path_readings``) is ``setup.py`` or
    ``<top dir>/setup.py``. A wheel's setup.py is never run by pip."""
    if ctx.pkg.ecosystem != "pypi" or ctx.archive_kind != "sdist":
        return False
    return any(_SETUP_PY.fullmatch(r) for r in path_readings(m.raw_path or m.path))


def _octet_readings(octet: str) -> set[int]:
    """Values a URL host octet may take: decimal, and the octal reading
    inet_aton gives a leading zero (0127 is 87). Out-of-range values stay in
    and make the address invalid."""
    values = {int(octet, 10)}
    if len(octet) > 1 and _OCTAL.fullmatch(octet):
        values.add(int(octet, 8))
    return values


def is_public_ipv4_url(matched: bytes) -> bool:
    """True if the IPv4 literal in an ``http(s)://a.b.c.d`` match is a global
    address under ANY plausible reading of its octets (when in doubt, keep
    the sink). Loopback, private, link-local, CGNAT, documentation and
    reserved addresses are not sinks; nor is an octet above 255."""
    found = _IPV4.search(matched)
    if found is None:
        return False
    readings: list[list[int]] = [[]]
    for octet in found.groups():
        readings = [r + [v] for r in readings for v in _octet_readings(octet.decode())]
    for octets in readings:
        if any(v > 255 for v in octets):
            continue
        if ipaddress.IPv4Address(bytes(octets)).is_global:
            return True
    return False


def _compile(script_rules: bool) -> yara.Rules:
    root = resources.files("eslabon").joinpath("rules")
    with resources.as_file(root) as rule_dir:
        paths = {
            p.stem: str(p)
            for p in sorted(rule_dir.glob("*.yar"))
            if (p.stem in _SCRIPT_ONLY) == script_rules
        }
        if not paths:
            raise RuntimeError("no YARA rules bundled")
        return yara.compile(filepaths=paths, error_on_warning=True)


def compile_rules() -> yara.Rules:
    """Compile the bundled ``rules/*.yar`` that run on archive members (every
    file except the script-only namespaces); a YARA warning is an error."""
    return _compile(script_rules=False)


def compile_script_rules() -> yara.Rules:
    """Compile the namespaces that only run on npm lifecycle script strings
    (``esl002``). Kept out of ``compile_rules`` so they never see a member."""
    return _compile(script_rules=True)


def counted_offsets(match: yara.Match) -> list[int]:
    """Offsets of the instances of ``match`` that count (empty: no finding).

    For the ESL-004 namespace an IP-literal sink instance counts only if the
    address is public, and the match is void when no sink instance is left.
    Every other namespace counts every instance as matched."""
    ip_string = _IP_FILTERED.get(match.namespace)
    offsets: list[int] = []
    sinks = 0
    verdicts: dict[bytes, bool] = {}  # dense repeats of one IP parse once
    for s in match.strings:
        keep_all = s.identifier != ip_string or len(s.instances) >= _YARA_MATCH_CAP
        for inst in s.instances:
            hit = inst.matched_data
            if not keep_all:
                if hit not in verdicts:
                    verdicts[hit] = is_public_ipv4_url(hit)
                if not verdicts[hit]:
                    continue
            if s.identifier.startswith(_SINK_PREFIX):
                sinks += 1
            offsets.append(inst.offset + _leading_space(hit))
    if ip_string is not None and sinks == 0:
        return []  # every sink was a non-public IP: no exfiltration target
    return offsets


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
    setup_py: bool | None = None  # computed lazily, only if needed
    for match in matches:
        if match.namespace in _SETUP_PY_ONLY:
            if setup_py is None:
                setup_py = is_install_setup_py(m, ctx)
            if not setup_py:
                continue
        esl_id = match.meta["esl_id"]
        for off in counted_offsets(match):
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
