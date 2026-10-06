"""E7: trim the Kali agent ossec.conf to the Eslabon snippet only.

Usage: sudo python3 trim_agent_conf.py <ossec.conf> <snippet>
Keeps <client> (manager address, enrollment). Removes every <localfile>,
disables syscheck, rootcheck, syscollector and sca, then adds the snippet
as the only <localfile>. Writes <ossec.conf>.orig first.
"""
import re
import shutil
import sys
from pathlib import Path


def set_in_block(text, open_re, close_tag, old, new):
    m = re.search(open_re + r".*?" + re.escape(close_tag), text, re.S)
    if not m or old not in m.group(0):
        raise SystemExit("block not found or already changed: " + open_re)
    block = m.group(0).replace(old, new, 1)
    return text[: m.start()] + block + text[m.end():]


def main():
    conf, snippet = Path(sys.argv[1]), Path(sys.argv[2])
    text = conf.read_text(encoding="utf-8")
    shutil.copy2(conf, str(conf) + ".orig")
    text, n = re.subn(r"[ \t]*<localfile>.*?</localfile>[ \t]*\n?", "", text, flags=re.S)
    print("removed localfile blocks:", n)
    off = "<disabled>no</disabled>"
    on = "<disabled>yes</disabled>"
    text = set_in_block(text, r"<syscheck>", "</syscheck>", off, on)
    text = set_in_block(text, r"<rootcheck>", "</rootcheck>", off, on)
    text = set_in_block(text, r'<wodle name="syscollector">', "</wodle>", off, on)
    text = set_in_block(text, r"<sca>", "</sca>", "<enabled>yes</enabled>", "<enabled>no</enabled>")
    snip = snippet.read_text(encoding="utf-8").strip()
    snip = "\n".join("  " + line for line in snip.splitlines())
    idx = text.index("</ossec_config>")
    text = text[:idx] + snip + "\n" + text[idx:]
    conf.write_text(text, encoding="utf-8")
    assert text.count("<localfile>") == 1, "expected exactly one localfile"
    assert "/var/log/eslabon/events.jsonl" in text
    assert re.search(r"<address>[^<]+</address>", text), "client address lost"
    print("ok: one localfile, client address kept")


if __name__ == "__main__":
    main()
