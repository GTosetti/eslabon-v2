"""Sanitise attacker-controlled text before it reaches a terminal or a SIEM."""

import re

# CSI (ESC [ params final), OSC (ESC ] ... BEL | ESC \), or any lone ESC.
_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"
    r"|\x1b"
)
# C0 (except \t), DEL, C1, bidi embeddings/isolates, LRM/RLM/ALM.
_CONTROLS = re.compile(
    r"[\x00-\x08\x0a-\x1f\x7f-\x9f‪-‮⁦-⁩‎‏؜]"
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
