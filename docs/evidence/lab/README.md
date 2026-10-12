# Lab evidence: Eslabon v2 end to end on Wazuh (2026-10-06)

The end-to-end lab run measures one event stream at four layers. Generated
on Kali, collected by the manager (`archives.json`), alerted by the rules engine
(`alerts.json`) and indexed in `wazuh-alerts-*`.

**Result.** Pass 1 (scanner `e660c1e`) gave 14 = 14 = 14 and **0 indexed**. Every alert
was rejected by the indexer, and that finding produced the fixes in commits `368a8a0`
and `7b981f9`. Pass 2 (scanner `7b981f9`) gave **14 = 14 = 14 = 14**. Kali and the manager
were restored to their snapshots afterwards.

## Environment

This lab is not the author's main home lab (Wazuh 4.14.7 on a 10.10.10.0/24 NAT network).
The user decided to run the lab on the VMs of this host.

| Item | Value |
|---|---|
| Host | Windows 11, VirtualBox 7.2.20r175154 on Hyper-V (NEM) |
| Manager | Wazuh OVA, `WAZUH_VERSION="v4.14.0"`, `WAZUH_REVISION="rc2"` (Amazon Linux, kernel 6.1), 192.168.56.101 |
| Agent host | Kali 2026.2, Python 3.13.12, 192.168.56.102. Network: VirtualBox Host-Only 192.168.56.0/24 |
| Agent | `wazuh-agent=4.14.0-1`, the same version as the manager, ID 001, `apt-mark hold` |
| Agent config | the `<client>` block is kept. All 10 default `<localfile>` blocks are removed, and syscheck, rootcheck, syscollector and sca are disabled. Only `integrations/wazuh/agent-ossec.conf.snippet` remains (`scripts/trim_agent_conf.py`; its output `removed localfile blocks: 10` is session output, not saved). In `kali-state.txt`, line 169 `log_format plain` belongs to the `<logging>` block (the agent's own log format), not to a second `<localfile>` |
| Rules | `/var/ossec/etc/rules/eslabon_v2_rules.xml`, `wazuh:wazuh` 660, installed with `install -o wazuh -g wazuh -m 660` and followed by `wazuh-analysisd -t` (exit 0). Repo sha256: pass 1 `59aef6ae...b346` (`git show e660c1e:integrations/wazuh/eslabon_v2_rules.xml \| sha256sum`), pass 2 `ae80987d...525c` (`7b981f9`). The manager-side `sha256sum` and `ls -l` matched, but that output was seen in the session and not saved |
| Index access | indexer admin certificate from inside the manager. No password was used or stored |

Some values in this README come from session output that was **not saved to a file**:
the VirtualBox version, the Kali IP, the OVA kernel, the manager disk numbers, the snapshot
incidents, the manager-side rules hash and permissions and `wazuh-analysisd -t` exit 0,
the `authd` lines quoted under Incidents and Clean-up, the trimming script's output and
the pass 2 filebeat filter (`grep "Cannot index event" /var/log/filebeat/filebeat | grep -c
"2026-10-06T2[0-9]:"`, run at 20:02:59Z, before experiment D). They are recorded in the
project's private working notes. Everything in the count and check tables below has a raw file.
Files named `*TRANSCRIPTION*` in their header are verbatim copies of terminal output from
VMs that were restored afterwards.

The manager needed one repair before the lab could run. Its
25 GB disk was 100% full because of the vulnerability-detection feed
(`queue/vd_updater/tmp`, 13 GB). Vulnerability detection was disabled, the temporary
files were emptied, and the cold snapshot `base-vd-off` was taken. That snapshot is the
clean-up target.

## Three-layer counts (plus the index)

The counts are filtered by the 8 `scan_id`s of each pass, so earlier events are never
counted. Command: `count_events.py <scan_ids>`, run on the manager (`scripts/count_events.py`).
The index query is printed inside each counts file.

| Layer | Pass 1 `e660c1e` | Pass 2 `7b981f9` | Files |
|---|---|---|---|
| Generated, Kali `events.jsonl` | 14 | 14 | `generation-pass*.txt` |
| Collected, `archives.json`, location `events.jsonl`, decoder `json` | 14 | 14 | `counts-pass*.txt` |
| Alerted, `alerts.json` | 14 | 14 | `counts-pass*.txt` |
| Indexed, `wazuh-alerts-*` (`rule.groups=eslabon_v2` + `scan_id`s) | **0** | **14** | `counts-pass*.txt` |

All 14 events break down the same way in both passes:

| Events | Count | Wazuh rule | Level |
|---|---|---|---|
| ESL-001..006 findings | 1 each | 100301..100306 | 11, 11, 12, 12, 7, 13 |
| `ok` summaries | 7 | 100310 | 3 |
| `incomplete` summary | 1 | 100311 | 7 |

ESL-006 fired **live**. The synthetic archive declares `paypalize` 1.0.0, OSV returned
a `MAL-` advisory, and nothing malicious was downloaded. The alert (100306) and exit code
1 are evidenced. The advisory ID was not captured from these scans; the pre-flight live
query returned `MAL-2025-28954` (session output, not saved). Exit codes were 1 for the
finding scans, 0 for the clean one and 2 for the incomplete one.

**Why pass 1 had 0 indexed** (`filebeat-pass1-e660c1e.txt`). There were 14 `Cannot index
event` lines, all of them
`mapper_parsing_exception: failed to parse field [data.file] of type [keyword]`.
The `wazuh` index template maps `data.file` as `keyword`, while the event carried an
object, `file.hash.sha256`. The rules engine had already alerted; only the dashboard
never saw the alerts. Commit `368a8a0` moved the hash to `eslabon.archive.sha256`. In pass 2 there
were 0 such errors.

## wazuh-logtest

There is one output file per sample, for each pass, in `logtest/`. Command:
`sudo /var/ossec/bin/wazuh-logtest -l /var/log/eslabon/events.jsonl < sample.jsonl`.
The samples come from `scripts/make_logtest_samples.py`, run on Kali. Snippet values are
redacted, because the repository guard must never see the synthetic payloads.

- All 9 samples reach the expected leaf in both passes (table in
  `integrations/wazuh/README.md`).
- Pass 1 prints `WARNING: Mitre Technique ID 'T1027.013' not found in database.` for
  ESL-003. Pass 2 has no warning: `wazuh_mitre` is overridden to `T1027`.
- Pass 1 groups were `['eslabon_v2', 'eslabon_v2', 'supply_chain']`. Pass 2 groups are
  `['eslabon_v2', 'supply_chain']`.
- `logtest/pass1-e660c1e/esl-003-verbose.txt` (`-v`) shows the path
  `1 -> 100300 -> 100303`. Rule 1002 is never tried before 100300.

## Design section 11 checks

| Check | Result | Evidence |
|---|---|---|
| Our fields are stored as `data.rule.*`, separate from Wazuh's `rule.*` | **Confirmed.** `rule.id=100303`, `data.rule={"id":"ESL-003","name":"encoded-exec",...}` | `counts-pass*.txt` (sample alert) |
| How a `<field>` matches a string array (`threat.technique.id`) | **Confirmed by probe**: the decoder stores the array as one string, `['T1027.013', 'T1140']`. A throwaway rule with `^T1140$` did **not** match; an unanchored `T1140` did (rule 100396 won). In the alert JSON it is a real array. No Eslabon rule depends on it | `probes.txt` (probe ARR), `scripts/probe_rules.xml`; phase 2 in `logtest/*/esl-003.txt` |
| `$(rule.name)` and `$(package.name)` interpolate | **Confirmed.** Example: `Eslabon v2: ESL-003 encoded-exec in package demo (demo-0.0.1/setup.py)` | `logtest/*` |
| `T1027.013` and `T1546.016` exist in Wazuh's ATT&CK db | **T1027.013 contradicted** (WARNING, absent; the db uses pre-v18 names, e.g. *Defense Evasion*). **T1546.016 confirmed** (*Installer Packages*) | `logtest/pass1-*/esl-003.txt`, `esl-001.txt` |
| `negate="yes"` in rule 100311 | **Confirmed** for a present field: `ok` reaches 100310; `incomplete` and `osv_unavailable` reach 100311. **Absent field (left open when the rules were written): the negated rule does NOT match.** The probe with no `eslabon.scan.status` matched no rule, while the control with `status=incomplete` matched (100395). So 100311 relies on the schema requiring `eslabon.scan.status` in every summary. (The probe rule's description text, "matched although ... absent", was written for the ABS case; in `probes.txt` it is printed for the PRES control, where the field is present.) | `logtest/*/scan-*.txt`; `probes.txt` (probes ABS, PRES) |
| A 70 KB line and a UTF-8 BOM | **70 KB: the line is dropped, not truncated** (and one more line is lost). **BOM: confirmed harmless** (stripped, decoder `json`). Details in Experiments | `experiments-abc-per-marker.txt`, `counts-experiment*.txt`, `kali-state.txt` |
| Kali `python3` is 3.14 (no yara-python wheel) | **Contradicted.** Kali has 3.13.12, and the `yara-python 4.5.4` cp313 manylinux wheel installed. The full suite on Kali: 975 passed, 9 skipped (Windows-only path tests) and 3 deselected (network, by `addopts`); 975 + 9 = 984, the host's non-network count (host run at e660c1e: `984 passed, 3 deselected`, session output; pass 2 host run at 7b981f9: 1001 passed). Run at `e660c1e` only; pass 2 checked the tar hash and `MAX_LINE_BYTES` | `kali-state.txt` (version); `kali-install-and-suite.txt` (wheel, suite; TRANSCRIPTION) |
| (README) No built-in json rule claims these events before 100300 | **Confirmed** for the ESL-003 sample: rule 1002 is never tried before 100300 (the pre-flight source reading predicted it would be). Other samples were run without `-v`; all reached their leaf, which is consistent | `logtest/pass1-e660c1e/esl-003-verbose.txt` |

## Experiments

Each experiment writes one line of the given size plus two small sentinel lines to the
monitored file in a single write (`scripts/experiments.py`, standing in for the planned
`scripts/oversize_line.py`). The sentinels are scan summaries with no `file` object, so
they are indexable.

| Experiment | Big line | Sentinel 1 | Sentinel 2 | Agent `ossec.log` |
|---|---|---|---|---|
| A: 70,000 B | dropped silently | delivered, alerted | **lost** | `ERROR: Large message size ... (length = 219)`, which blames a 219-byte sentinel, not the big line |
| B: 65,300 B (old emitter cap allowed it) | dropped silently | delivered, alerted | **lost** | same misleading error |
| C: rotate, new file starting with a UTF-8 BOM, + 2 lines | n/a | both lines delivered and alerted, decoder `json` | | nothing (the BOM is stripped) |
| D: 65,000 B (new `MAX_LINE_BYTES`) | delivered and alerted, **but not indexed** | delivered, alerted | delivered, alerted | no error (session output: `tail -n 3` of the agent log after D showed no `Large message`; not saved) |

Per-marker collected/alerted results for A-C are in `experiments-abc-per-marker.txt`
(a TRANSCRIPTION; the manager logs were discarded by the snapshot restore). For D they
are in `counts-experiment-d.txt`. **Indexing was only counted in aggregate**: A-C gave
`hits.total` 4, which equals the 4 collected markers (`counts-experiments-abc.txt`), and D
gave 2 of 3. The missing D document is the big line, identified by its filebeat
rejection in `manager-state.txt`. Per-marker indexing was not queried.

- **A and B.** Measured: the big line and sentinel 2 are lost, sentinel 1 arrives, and
  one `Large message size (length = 219)` error is logged. Interpretation (consistent with
  the read_json source read in the pre-flight, not proven by these files): the oversized
  line is dropped rather than truncated, the following line is delivered but reported as
  oversized, and the line after it is consumed.
  This is why commit `368a8a0` lowered `MAX_LINE_BYTES` from 65,536 to 65,000.
- **D.** This is a second, per-field limit. The `wazuh` template maps every dynamic
  string as `keyword` with no `ignore_above`, and one 64,780-byte string value made
  OpenSearch reject the whole alert: `max_bytes_length_exceeded_exception: bytes can be
  at most 32766` in `data.eslabon.pad` (`manager-state.txt`). Eslabon's real string
  fields are capped at 512 or 1,024 characters (at most about 4 KB in UTF-8), so its
  events cannot reach this limit. A test that pins "every emitted string is 32,766 bytes
  or less" is listed under Follow-ups below.

## Clean-up (verified)

1. `logall_json` was set back to `no` (the `ossec.conf` copy taken before the lab was restored) and
   the manager was restarted.
2. `manage_agents -r 001`, which first had to be **repeated**. The Kali agent was still
   running, so it re-enrolled automatically (`authd` logged a new agent key for it)
   and got ID 001 again. **The correct order is to stop the agent first, then remove
   it.** After the second removal `client.keys` was empty, and `agent_control -l` listed
   only `000`.
3. Both VMs were shut down through ACPI. Kali was restored to `pre-eslabon-v2` and the
   manager to `base-vd-off`.

Steps 1 and 2 are session output; the restored state is captured. After the review, both
VMs were booted from their restored snapshots to capture that state and to run the
section 11 probes, then shut down and **restored again**:

- `manager-after-cleanup.txt`: `client.keys` has 0 lines, `agent_control -l` lists only
  000, `logall_json` is `no`, there is no `eslabon_v2_rules.xml`, and VD is disabled.
- `kali-after-cleanup.txt`: no `wazuh-agent` package, no `/var/ossec`,
  `/var/log/eslabon`, `~/eslabon`, lab working directory or Wazuh apt list.
- `host-snapshots-final.txt`: no VM running, Kali current snapshot `pre-eslabon-v2`, and
  manager current snapshot `base-vd-off`. Both `.vbox` files have
  `currentStateModified="false"` and were written at 20:38:29Z, the final restore. That
  is after the probe file was installed (20:35:07Z), so the probe rules are gone.

## Deviations from the lab plan

| Plan | What was done | Why |
|---|---|---|
| Main home lab (Wazuh 4.14.7, 10.10.10.10, SOCLAB) | Wazuh OVA 4.14.0 rc2 on a Host-Only network; agent 4.14.0-1 | The user's decision to use this host's VMs |
| Snapshot Kali only | Both VMs snapshotted; manager repaired, then `base-vd-off` | The OVA was unknown and broken (disk full) |
| Index via the dashboard console proxy with a `@timestamp` range | Indexer on 127.0.0.1:9200 inside the manager, with the admin certificate, filtered by `scan_id` | No password in chat or files (user-approved). The index `@timestamp` is the manager's alert time, so `scan_id` is exact |
| Logtest samples generated on the host (`integrations/wazuh/README.md`) | Generated on Kali | Design section 8: suspicious-looking fixtures are built only in Kali |
| `scripts/oversize_line.py` | `scripts/experiments.py` (evidence script, oversize + BOM) | The planned script never existed; this evidence script is the one that ran, so it stays with the evidence rather than in `scripts/` |
| One measurement pass | Two passes (`e660c1e`, `7b981f9`) | Pass 1 found the `data.file` rejection, which led to the fixes in `368a8a0` and `7b981f9` |
| Planned order: restore Kali, then `manage_agents -r` | `manage_agents -r` with the agent still running, so it re-enrolled, then stop + remove again, then restore | Lesson: **stop the agent before removing it**. Recorded in `integrations/wazuh/README.md` ("Remove (clean-up)") |

## Incidents during the session

- A **live** snapshot of the manager never converged under Hyper-V/NEM: it stayed at
  90% for about 45 minutes while dirty pages were re-copied. Pausing the VM aborted it
  with `VERR_VM_UNEXPECTED_UNSTABLE_STATE` and left the guest kernel in an RCU stall.
  The VM was recovered by restoring the cold snapshot and redoing the repair. Lesson:
  take only **cold** snapshots on this host.
- After a cold boot, `wazuh-manager` can hit its systemd start timeout while the
  indexer is starting (2 vCPU). `systemctl restart wazuh-manager` fixes it.
- `wazuh-authd: SSL handshake failed` lines at 18:53 come from TCP port probes against
  1515 run from the host during setup checks. They are not an attack.

## Files

| File | Content |
|---|---|
| `generation-pass*.txt` | Kali: fixture sha256, scan commands, exit codes, per-rule counts, scan_ids |
| `counts-pass*.txt` | manager: archives / alerts / index counts, the index DSL and a sample alert |
| `filebeat-pass1-e660c1e.txt` | the 14 indexer rejections of pass 1 |
| `counts-experiments-abc.txt` | experiments A-C, aggregate only (total 4, hits 4) |
| `counts-experiment-d.txt` | experiment D, aggregate plus per-marker collected/alerted |
| `manager-state.txt` | experiment D rejection, the `wazuh` template's `dynamic_templates` and `data.file` mapping, `agent_control -l`, version |
| `kali-state.txt` | Python version, agent package and hold, agent `ossec.log` (enrolment, file, errors), trimmed config |
| `kali-install-and-suite.txt` | TRANSCRIPTION: tar hashes, yara-python wheel, the suite on Kali, `MAX_LINE_BYTES` in pass 2 |
| `experiments-abc-per-marker.txt` | TRANSCRIPTION: per-marker collected/alerted counts for experiments A-C, and their commands |
| `probes.txt` | section 11 probes: array matching and negate on an absent field (plus a positive control) |
| `manager-after-cleanup.txt`, `kali-after-cleanup.txt`, `host-snapshots-final.txt` | the restored state, captured |
| `logtest/` | wazuh-logtest output per sample and pass (snippets redacted) |
| `scripts/` | the scripts used: fixtures, scans, counts, experiments, agent trimming, probes |

### Names in the raw captures

The raw captures and scripts are kept byte-identical, so they still use the names they
had when they ran. The working directory on Kali was `~/e7`, the agent was named
`kali-e7`, the evidence folder was `docs/evidence/e7/`, and experiment and probe markers
carry an `e7` prefix. The scripts were renamed afterwards:

| Name in the captures | Current file |
|---|---|
| `build_e7_fixtures.py` | `scripts/build_fixtures.py` |
| `run_e7_scans.sh` | `scripts/run_scans.sh` |
| `count_e7.py` | `scripts/count_events.py` |
| `exp_e7.py` | `scripts/experiments.py` |
| `e7_probe_rules.xml` | `scripts/probe_rules.xml` |
| `e7_probe_samples.sh` | `scripts/probe_samples.sh` |

## Follow-ups found in the lab

- A test pinning that every emitted string is 32,766 UTF-8 bytes or less (experiment D).
- `integrations/wazuh/README.md`: stop the agent before
  `manage_agents -r`; `wazuh-logtest -l` confirmed; the T1027 substitution recorded.
- The rule 100311 docs: it never fires for a summary without `eslabon.scan.status`
  (probe ABS). The schema requires that field, so this is documentation, not a bug.
