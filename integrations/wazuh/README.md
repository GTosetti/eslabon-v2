# Eslabon v2 on Wazuh 4.14

| File | Goes to |
|---|---|
| `eslabon_v2_rules.xml` | manager: `/var/ossec/etc/rules/eslabon_v2_rules.xml` |
| `agent-ossec.conf.snippet` | Kali agent: the only `<localfile>` in `/var/ossec/etc/ossec.conf` |
| logtest samples | generated on demand, see below (never committed) |

## Coexistence with eslabon v1

The lab manager already runs eslabon v1: rule IDs 100100-100170, group `eslabon`,
base rule limited to `<location>eventos.jsonl$</location>`. v2 uses its own file,
IDs **100300-100399**, group **`eslabon_v2`** and the log path
`/var/log/eslabon/events.jsonl`. v1's rule file is never edited.

## Rule tree

Wazuh emits **one alert per event**, so each event reaches exactly one leaf:

| ID | Level | Matches | Alert |
|---|---|---|---|
| `100300` | 0 | `json` decoder, location `events.jsonl$`, `event.module` = `eslabon` | parent, no alert |
| `100301` | 11 | finding, `rule.id` = `ESL-001` (pypi-install-exec) | T1546.016, T1059.006 |
| `100302` | 11 | finding, `ESL-002` (npm-install-script-exec) | T1546.016, T1059.007 |
| `100303` | 12 | finding, `ESL-003` (encoded-exec) | T1027, T1140 (the event carries T1027.013) |
| `100304` | 12 | finding, `ESL-004` (secret-exfil) | T1552.001, T1041 |
| `100305` | 7 | finding, `ESL-005` (typosquat) | T1195.001 |
| `100306` | 13 | finding, `ESL-006` (known-malicious); also the Sigma translation | T1195.001 |
| `100310` | 3 | scan summary, `eslabon.scan.status` = `ok` | lowest indexed level, so it can be counted |
| `100311` | 7 | scan summary, any other status (`negate="yes"`) | |

**`100311` needs the status field to exist.** Its `negate="yes"` on
`eslabon.scan.status` does **not** match when the field is absent. Measured in E7 with
a throwaway probe rule, 100395, that used the same negated field
(`<field name="eslabon.scan.status" type="pcre2" negate="yes">^ok$</field>`) under its
own parent conditions (`event.module` = `e7probe`, no `if_sid`): a line with no
`eslabon.scan.status` reached no rule, while the control with `incomplete` reached
100395 (`docs/evidence/e7/probes.txt`, `docs/evidence/e7/scripts/e7_probe_rules.xml`). So a summary without a status would
raise no alert at all. The rule relies on the event schema, which **requires**
`eslabon.scan.status` in every summary (`schema/event.schema.json`); `summary_event`
in `src/eslabon/emit.py` always writes it.

Levels and `<mitre>` IDs come from `src/eslabon/catalog.toml` (`wazuh_level`,
`wazuh_mitre`); `tests/test_integrations.py` fails if they drift. No rule is level 15.
`wazuh_mitre` defaults to the rule's `techniques`; a rule overrides it only where
Wazuh's database lacks an ID (see "ATT&CK version").

**Groups.** Every rule gets `eslabon_v2` from the file-level `<group name="eslabon_v2,">`
only; the per-rule `<group>` adds just `supply_chain`, `sigma` or `scan_summary`.
Repeating `eslabon_v2` inside a rule made the alert's `rule.groups`
`['eslabon_v2', 'eslabon_v2', 'supply_chain']` in E7.

**`rule.id` and `rule.name` in the XML are our JSON fields.** In the alert they are
stored under `data.rule.*`, next to Wazuh's own `rule.id` (`1003xx`). This is the
first thing to confirm in E7.

**Matching semantics.** `<location>` is OS_Match: a literal, case-insensitive
compare where only a leading `^` and a trailing `$` are special and a backslash is
**not** an escape (so `events\.jsonl$` would never match). `events.jsonl$` is a
suffix compare that covers both the local form `/var/log/eslabon/events.jsonl` and
the form an agent event carries, `(<agent>) <ip>->/var/log/eslabon/events.jsonl`
(e.g. `(kali) any->/var/log/eslabon/events.jsonl`), and never matches v1's
`eventos.jsonl`. Every `<field>` is `type="pcre2"`: in the default OS_Regex, `\.`
means *any* character, so `^eslabon\.finding$` would also match `eslabonXfinding`.

## Install (manager)

```bash
sudo cp eslabon_v2_rules.xml /var/ossec/etc/rules/eslabon_v2_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/eslabon_v2_rules.xml
sudo chmod 660 /var/ossec/etc/rules/eslabon_v2_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t          # config test: must print nothing bad
sudo systemctl restart wazuh-manager
```

Files under `etc/rules/` are loaded automatically (`<rule_dir>etc/rules</rule_dir>`
in the default `ossec.conf`); no `<include>` is needed.

## Install (Kali agent)

Trim `<localfile>` blocks in `/var/ossec/etc/ossec.conf` to the one in
`agent-ossec.conf.snippet`, so Kali's own logs do not pollute the counts, then:

```bash
sudo mkdir -p /var/log/eslabon
sudo systemctl restart wazuh-agent
```

## Remove (clean-up)

On the manager, delete `/var/ossec/etc/rules/eslabon_v2_rules.xml` and restart it. To
remove the Kali agent, **stop it first**, then delete its entry:

```bash
sudo systemctl stop wazuh-agent                  # on Kali, BEFORE the removal
sudo /var/ossec/bin/manage_agents -r <id>        # on the manager
sudo /var/ossec/bin/agent_control -l             # only 000 should be left
```

A running agent enrols again by itself and gets the same ID back, so a removal done
while it runs is undone. Measured in E7: `manage_agents -r
001` had to be repeated (`authd: Agent key generated for 'kali-e7'`).

## Test with wazuh-logtest

Generate the samples on the development host, from the repository root (they run
the real scanner over synthetic archives; the output dir must be outside the repository, because the
evidence snippets would trip our own repo guard):

```bash
.venv/Scripts/python.exe scripts/make_logtest_samples.py --out ../eslabon-logtest
```

| Sample | Must reach |
|---|---|
| `esl-001.jsonl` .. `esl-006.jsonl` | `100301` .. `100306` |
| `scan-ok.jsonl` | `100310` |
| `scan-incomplete.jsonl`, `scan-osv-unavailable.jsonl` | `100311` |

**Location matters.** `100300` requires the location to end in `events.jsonl`;
without `-l`, `wazuh-logtest` reports the location as `stdin`, which does **not**
match, and a pasted line stops at phase 2. So, on the manager:

```bash
sudo /var/ossec/bin/wazuh-logtest -l /var/log/eslabon/events.jsonl
```

and paste one line (`-l` sets the location, per the 4.14 `wazuh-logtest`
reference). Phase 2 must show `decoder: 'json'`; phase 3 must show the rule ID in
the table above, its level, and the `mitre` block.

Fallbacks, if `-l` does not behave as documented:
- the API, which takes the location explicitly:
  `PUT /logtest` with `{"event": "<line>", "log_format": "json", "location": "/var/log/eslabon/events.jsonl"}`;
- a temporary copy of the rule file with the `<location>` line removed, used only for
  the logtest session.

The end-to-end proof is the real path anyway: append a line to
`/var/log/eslabon/events.jsonl` on Kali and find the alert in `wazuh-alerts-*`.

## ATT&CK version

Wazuh's ATT&CK database is **v13.1** (since 4.8), so the dashboard shows older names,
e.g. *Defense Evasion* for TA0005 (the events carry v19.2's *Stealth*). Each `<mitre>`
ID must be checked in `wazuh-logtest` for "not found" warnings. If a sub-technique is
missing from Wazuh's database, its parent is used in the XML and this README says so.

Substitutions, measured in E7: **`T1027.013` -> `T1027` for rule `100303`** (logtest:
`WARNING: Mitre Technique ID 'T1027.013' not found in database.`). It is recorded as
`wazuh_mitre = ["T1027", "T1140"]` for ESL-003 in `catalog.toml`; the events keep
`T1027.013` in `threat.technique.id`.

## What to verify in E7 (design section 11)

| Check | How |
|---|---|
| The alert stores our fields as `data.rule.*`, separate from Wazuh's `rule.*` | `wazuh-logtest` phase 3 and the alert JSON |
| How a `<field>` matches against a string array (`threat.technique.id`) | no rule here depends on it; probe with a throwaway rule |
| `$(rule.name)` and `$(package.name)` interpolate in rule descriptions | the alert's `rule.description` |
| `T1027.013` and `T1546.016` exist in Wazuh's v13.1 ATT&CK database | logtest warnings; fall back to `T1027` / `T1546` if not |
| What a 70 KB line and a UTF-8 BOM do at each layer | agent, logtest, alert |
| Kali's `python3` version: 3.14 has no `yara-python` wheel | `python3 --version` on Kali |

Also worth recording: that `negate="yes"` on `<field>` behaves as expected for
`100311`, and that no built-in json rule claims these events before `100300`. Both were
checked in E7 (`docs/evidence/e7/README.md`): negate works on a present field and does
not match an absent one (see "Rule tree" above), and rule 1002 was never tried before
`100300` in the `-v` trace of the ESL-003 sample.
