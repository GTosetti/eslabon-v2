from eslabon.sanitize import clean_text, to_hex


def test_strips_newline_ansi_bidi_nul():
    assert clean_text("a\nb\x1b[31mc‮d\x00e") == "abcde"


def test_strips_osc_c1_lrm_keeps_tab():
    assert clean_text("a\x1b]0;title\x07b\x85c‎d\te\r") == "abcd\te"
    assert clean_text("a\x1b]0;t\x1b\\b\x1bc") == "abc"


def test_truncates_after_decoding_never_splits_utf8():
    assert clean_text("é" * 2000, 1024) == "é" * 1024
    assert clean_text("é".encode() * 2000, 1024) == "é" * 1024


def test_invalid_utf8_replaced():
    assert clean_text(b"\xff\xfeok").endswith("ok")


def test_to_hex_roundtrip():
    assert bytes.fromhex(to_hex("../x")).decode() == "../x"
    assert to_hex("A") == "41"


def test_strips_line_separators():
    assert clean_text("a b c") == "abc"


def test_sanitize_source_is_ascii():
    from pathlib import Path

    import eslabon.sanitize as mod

    data = Path(mod.__file__).read_bytes()
    assert all(b < 0x80 for b in data)


def test_strips_zero_width_and_tag_chars():
    assert clean_text("a\U000e0041b​c﻿d") == "abcd"
    assert clean_text("a‌‍⁠­b\U000e007f") == "ab"


def test_no_esc_survives():
    assert "\x1b" not in clean_text("\x1b\x00[31mX")
    assert "\x1b" not in clean_text("\x1b[" * 200_000, max_len=10**7)

