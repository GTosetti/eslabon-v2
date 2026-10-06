#!/bin/sh
# E7 probes, run on the manager (snapshot restored afterwards).
set -u
echo "# installed probe file:"
sudo install -o wazuh -g wazuh -m 660 /tmp/e7_probe_rules.xml /var/ossec/etc/rules/e7_probe_rules.xml
sudo ls -l /var/ossec/etc/rules/
sudo /var/ossec/bin/wazuh-analysisd -t && echo "analysisd -t OK"
sudo systemctl restart wazuh-manager && systemctl is-active wazuh-manager
ARR='{"event":{"module":"e7probe"},"threat":{"technique":{"id":["T1027.013","T1140"]}}}'
ABS='{"event":{"module":"e7probe","dataset":"eslabon.scan"},"eslabon":{"scan_id":"probe"}}'
PRES='{"event":{"module":"e7probe","dataset":"eslabon.scan"},"eslabon":{"scan":{"status":"incomplete"}}}'
for name in ARR ABS PRES; do
    eval "line=\$$name"
    echo "== probe $name: $line"
    echo "$line" | sudo /var/ossec/bin/wazuh-logtest -l /var/log/eslabon/events.jsonl 2>&1 \
        | grep -E "threat.technique.id|eslabon.scan.status|^\s+(id|description): |No rule matched|Alert to be generated"
done
