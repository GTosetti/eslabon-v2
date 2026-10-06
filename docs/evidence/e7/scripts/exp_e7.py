"""E7 experiments on the monitored file (stand-in for the planned scripts/oversize_line.py).

Usage: python3 exp_e7.py oversize <total_bytes> <tag>   # one line of exactly total_bytes
                                                       # (incl. newline) + 2 sentinels, one write
       python3 exp_e7.py bom <tag>                     # rotate events.jsonl, new file = BOM + 2 lines
Lines are minimal Eslabon-shaped scan summaries (no "file" object), marked by scan_id.
"""
import json
import os
import sys
import time

PATH = "/var/log/eslabon/events.jsonl"


def event(scan_id, pad=""):
    ev = {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": {"module": "eslabon", "dataset": "eslabon.scan", "kind": "event"},
        "package": {"name": "e7-experiment"},
        "eslabon": {"scan_id": scan_id, "scan": {"status": "ok", "findings": 0}, "pad": pad},
    }
    return json.dumps(ev, separators=(",", ":"))


def sized(scan_id, total):
    base = len(event(scan_id).encode()) + 1
    line = event(scan_id, "x" * (total - base))
    assert len(line.encode()) + 1 == total, len(line.encode())
    return line


def main():
    mode = sys.argv[1]
    if mode == "oversize":
        total, tag = int(sys.argv[2]), sys.argv[3]
        lines = [sized(tag + "-big", total), event(tag + "-s1"), event(tag + "-s2")]
        data = ("\n".join(lines) + "\n").encode()
        with open(PATH, "ab") as f:
            f.write(data)
        print("wrote", [len(x.encode()) + 1 for x in lines], "bytes per line in one write")
    elif mode == "bom":
        tag = sys.argv[2]
        os.rename(PATH, PATH + ".1")
        data = b"\xef\xbb\xbf" + (event(tag + "-1") + "\n" + event(tag + "-2") + "\n").encode()
        with open(PATH, "wb") as f:
            f.write(data)
        os.chmod(PATH, 0o644)
        print("rotated to", PATH + ".1", "; new file starts with", data[:4])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
