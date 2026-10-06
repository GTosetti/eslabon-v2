#!/bin/bash
# E7 generate step: one eslabon scan per fixture, appended to the monitored file.
# Records exit codes, copies only the NEW lines to ~/e7/generated.jsonl and counts them.
set -u
E=~/eslabon/.venv/bin/eslabon
PY=~/eslabon/.venv/bin/python
F=~/e7/fixtures
OUT=/var/log/eslabon/events.jsonl
before=$(wc -l < "$OUT")
echo "lines before: $before"
run() {
    echo "+ eslabon scan $*"
    "$E" scan "$@" --out "$OUT" > /dev/null
    echo "  exit=$?"
}
run "$F/esl001/pkg-1.0.tar.gz" --ecosystem pypi --offline
run "$F/esl002/demo-1.0.0.tgz" --ecosystem npm --offline
run "$F/esl003/demo-0.0.1.tar.gz" --ecosystem pypi --offline
run "$F/esl004/demo-1.0.0.tgz" --ecosystem npm --offline
run "$F/esl005/reqeusts-1.0.tar.gz" --ecosystem pypi --offline
run "$F/esl006/paypalize-1.0.0.tgz" --ecosystem npm
run "$F/clean/left-pad-1.0.0.tgz" --ecosystem npm --offline
run "$F/incomplete/pkg-1.0-py3-none-any.whl" --offline
after=$(wc -l < "$OUT")
echo "lines after: $after (new: $((after - before)))"
tail -n +"$((before + 1))" "$OUT" > ~/e7/generated.jsonl
"$PY" - <<'EOF'
import collections, json, os
lines = open(os.path.expanduser("~/e7/generated.jsonl"), encoding="utf-8").read().splitlines()
c = collections.Counter()
ids = []
for raw in lines:
    e = json.loads(raw)
    ds = e["event"]["dataset"]
    key = e["rule"]["id"] if ds == "eslabon.finding" else "status=" + e["eslabon"]["scan"]["status"]
    c[(ds, key)] += 1
    if e["eslabon"]["scan_id"] not in ids:
        ids.append(e["eslabon"]["scan_id"])
print("generated lines:", len(lines), "max bytes:", max(len(r.encode()) for r in lines))
for k in sorted(c):
    print("  %-16s %-22s %d" % (k[0], k[1], c[k]))
print("scan_ids (%d):" % len(ids), " ".join(ids))
EOF
