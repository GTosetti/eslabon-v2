"""E7 collect/detect counts on the manager, filtered by the session's scan_ids.

Usage: sudo python3 count_e7.py <scan_id> [<scan_id> ...]
Prints: archives.json (collected) and alerts.json (rules engine) counts, then
the wazuh-alerts-* index counts (queried with the indexer admin certificate).
"""
import collections
import json
import ssl
import sys
import urllib.request

IDS = set(sys.argv[1:])
CERTS = "/etc/wazuh-indexer/certs/"


def scan_id(ev):
    data = ev.get("data", ev)
    return (data.get("eslabon") or {}).get("scan_id")


def key(data):
    ds = (data.get("event") or {}).get("dataset")
    if ds == "eslabon.finding":
        return ds + " " + (data.get("rule") or {}).get("id", "?")
    return "%s status=%s" % (ds, ((data.get("eslabon") or {}).get("scan") or {}).get("status"))


def count_archives(path):
    c = collections.Counter()
    bad = 0
    for raw in open(path, encoding="utf-8", errors="replace"):
        if '"scan_id"' not in raw:
            continue
        try:
            ev = json.loads(raw)
        except ValueError:
            bad += 1
            continue
        if scan_id(ev) in IDS:
            loc = ev.get("location", "")
            c[(key(ev.get("data", {})), loc, ev.get("decoder", {}).get("name"))] += 1
    print("== archives.json (collected): total", sum(c.values()), "unparsable", bad)
    for k in sorted(c):
        print("  %-36s location=%s decoder=%s  %d" % (k[0], k[1], k[2], c[k]))


def count_alerts(path):
    c = collections.Counter()
    sample = None
    for raw in open(path, encoding="utf-8", errors="replace"):
        if '"scan_id"' not in raw:
            continue
        ev = json.loads(raw)
        if scan_id(ev) in IDS:
            r = ev["rule"]
            c[(r["id"], r["level"], (ev["data"].get("rule") or {}).get("id"), key(ev["data"]))] += 1
            if sample is None and r["id"] == "100303":
                sample = ev
    print("== alerts.json (rules engine): total", sum(c.values()))
    for k in sorted(c):
        print("  rule.id=%s level=%s data.rule.id=%s  [%s]  %d" % (k + (c[k],)))
    if sample:
        print("  sample 100303 rule.mitre:", json.dumps(sample["rule"].get("mitre")))
        print("  sample 100303 rule.groups:", sample["rule"].get("groups"))
        print("  sample 100303 data.rule:", json.dumps(sample["data"].get("rule")))
        print("  sample 100303 data.threat.technique:", json.dumps(sample["data"]["threat"]["technique"]))
        print("  sample 100303 timestamp:", sample.get("timestamp"), "data.@timestamp:", sample["data"].get("@timestamp"))


def count_index():
    ctx = ssl.create_default_context(cafile=CERTS + "root-ca.pem")
    ctx.load_cert_chain(CERTS + "admin.pem", CERTS + "admin-key.pem")
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": [
            {"term": {"rule.groups": "eslabon_v2"}},
            {"terms": {"data.eslabon.scan_id": sorted(IDS)}},
        ]}},
        "aggs": {
            "wazuh_rule": {"terms": {"field": "rule.id", "size": 50}},
            "esl_rule": {"terms": {"field": "data.rule.id", "size": 50}},
        },
    }
    req = urllib.request.Request(
        "https://127.0.0.1:9200/wazuh-alerts-*/_search",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    print("== wazuh-alerts-* (index) query:", json.dumps(body))
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        out = json.load(resp)
    print("  hits.total:", out["hits"]["total"])
    for name in ("wazuh_rule", "esl_rule"):
        b = out.get("aggregations", {}).get(name, {}).get("buckets", [])
        print("  agg %s: %s" % (name, [(x["key"], x["doc_count"]) for x in b]))


count_archives("/var/ossec/logs/archives/archives.json")
count_alerts("/var/ossec/logs/alerts/alerts.json")
count_index()
