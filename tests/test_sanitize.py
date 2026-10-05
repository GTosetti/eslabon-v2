from pathlib import Path

import eslabon.sanitize as mod
from eslabon.sanitize import clean_text, to_hex

# Special characters are built with chr() so this file stays pure ASCII.
RLO = chr(0x202E)
LRM = chr(0x200E)
LS = chr(0x2028)
PS = chr(0x2029)
ZWSP = chr(0x200B)
ZWNJ = chr(0x200C)
ZWJ = chr(0x200D)
WJ = chr(0x2060)
SHY = chr(0x00AD)
BOM = chr(0xFEFF)
TAG_A = chr(0xE0041)
TAG_DEL = chr(0xE007F)
E_ACUTE = chr(0xE9)


def test_strips_newline_ansi_bidi_nul():
    assert clean_text("a\nb\x1b[31mc" + RLO + "d\x00e") == "abcde"


def test_strips_osc_c1_lrm_keeps_tab():
    assert clean_text("a\x1b]0;title\x07b\x85c" + LRM + "d\te\r") == "abcd\te"
    assert clean_text("a\x1b]0;t\x1b\\b\x1bc") == "abc"


def test_truncates_after_decoding_never_splits_utf8():
    assert clean_text(E_ACUTE * 2000, 1024) == E_ACUTE * 1024
    assert clean_text(E_ACUTE.encode() * 2000, 1024) == E_ACUTE * 1024


def test_invalid_utf8_replaced():
    assert clean_text(b"\xff\xfeok").endswith("ok")


def test_to_hex_roundtrip():
    assert bytes.fromhex(to_hex("../x")).decode() == "../x"
    assert to_hex("A") == "41"


def test_strips_line_separators():
    assert clean_text("a" + LS + "b" + PS + "c") == "abc"


def test_sources_are_ascii():
    for path in (Path(mod.__file__), Path(__file__)):
        assert all(b < 0x80 for b in path.read_bytes()), path


def test_strips_zero_width_and_tag_chars():
    assert clean_text("a" + TAG_A + "b" + ZWSP + "c" + BOM + "d") == "abcd"
    assert clean_text("a" + ZWNJ + ZWJ + WJ + SHY + "b" + TAG_DEL) == "ab"


def test_no_esc_survives():
    assert "\x1b" not in clean_text("\x1b\x00[31mX")
    assert "\x1b" not in clean_text("\x1b[" * 200_000, max_len=10**7)
