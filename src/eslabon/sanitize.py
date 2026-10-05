"""Sanitise attacker-controlled text before it reaches a terminal or a SIEM."""

import re

# CSI (ESC [ params final), OSC (ESC ] ... BEL | ESC \), or any lone ESC.
_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"
    r"|\x1b"
)
# Ranges to drop: C0 (except TAB), DEL, C1, soft hyphen, ALM, zero-width, LRM/RLM,
# line/paragraph separators, bidi embeddings/isolates, word joiner, BOM, tag block.
# Built from integers so the source stays pure ASCII.
_STRIP_RANGES = (
    (0x00, 0x08), (0x0A, 0x1F), (0x7F, 0x9F), (0xAD, 0xAD), (0x61C, 0x61C),
    (0x200B, 0x200F), (0x2028, 0x202E), (0x2060, 0x2060), (0x2066, 0x2069),
    (0xFEFF, 0xFEFF), (0xE0000, 0xE007F),
)
_CONTROLS = re.compile(
    "[" + "".join(f"{chr(lo)}-{chr(hi)}" for lo, hi in _STRIP_RANGES) + "]"
)


def clean_text(raw: bytes | str, max_len: int = 1024) -> str:
    """Decode, strip control/bidi/ANSI content, then truncate to max_len characters."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    text = _ANSI.sub("", text)
    text = _CONTROLS.sub("", text)
    return text[:max_len]


def to_hex(raw: str) -> str:
    """Lowercase hex of the UTF-8 bytes (lossless form of an unsafe name)."""
    return raw.encode("utf-8", errors="surrogatepass").hex()
