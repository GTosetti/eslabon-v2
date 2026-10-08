# Eslabon

Eslabon statically inspects a PyPI or npm package **without installing or executing it**.
It emits one JSON Lines event per finding, shaped like ECS and mapped to MITRE ATT&CK
v19.2, so that a SIEM (Wazuh 4.14) can raise a triageable alert with evidence and a
mitigation. A chain is only as strong as its weakest link.

## How it differs

- **From DataDog GuardDog.** Eslabon does not out-detect GuardDog. GuardDog covers 7
  ecosystems with code and metadata heuristics, scans inside a kernel sandbox, and
  outputs JSON or SARIF with no ATT&CK technique mapping; its only SIEM path is
  Datadog's own. Eslabon's contribution is the alert: ECS-shaped, ATT&CK-mapped,
  evidence and mitigation included, validated end to end on a free SIEM. No GuardDog
  rule is copied.
- **From eslabon v1** ([github.com/GTosetti/eslabon](https://github.com/GTosetti/eslabon)).
  v1 is an orchestrator of external scanners. This version (v2, package version 0.1.0)
  has its own six heuristics. The two are designed to coexist on one Wazuh manager
  (not tested together): v2 uses rule IDs 100300-100399, group `eslabon_v2` and the log
  file `events.jsonl`; v1 uses 100100-100170, group `eslabon` and `eventos.jsonl`. v1's
  rules are never edited.

Other prior art and what Eslabon does not try to be: [`docs/design.md`](docs/design.md) §2.

## Quick start

Python **3.13** is required (`yara-python` 4.5.4, the only runtime dependency, has no
cp314 wheels). On Windows, from a clone of this repository:

```powershell
py -3.13 -m venv .venv
.venv\Scripts\pip.exe install .
```

Scan a local archive. `--offline` skips the OSV query (ESL-006) and records
`osv_status: skipped`; without it, OSV is queried:

```powershell
.venv\Scripts\eslabon.exe scan demo-clean-1.0.0.tgz --ecosystem npm --offline
.venv\Scripts\eslabon.exe scan demo-clean-1.0.0.tgz --ecosystem npm
```

Scan a package straight from the registry. It is downloaded over HTTPS into a temporary
directory outside the working tree, its registry hash is verified, it is scanned in
memory and deleted:

```powershell
.venv\Scripts\eslabon.exe scan requests==2.32.3 --ecosystem pypi --out req.jsonl
```

- `--ecosystem` is required, except for a `.whl` (always PyPI). Inputs: `.tar.gz`,
  `.tgz`, `.tar.bz2`, `.zip`, `.whl`, or `name==version`.
- Events are **appended** to `--out` (default: `events.jsonl` in the current
  directory). Every scan writes one summary event (`event.dataset: eslabon.scan`) plus
  one finding event per (rule, file); ESL-005 and ESL-006 judge the package, not a file,
  so their findings are per package name checked.
- Exit code: `0` clean, `1` findings, `2` error or incomplete scan. `2` wins over `1`.
  A usage error (for example a missing `--ecosystem`) prints one line on stderr, exits
  `2` and writes **no** event, not even a summary.

What a clean scan writes (one line, wrapped here):

```json
{"@timestamp":"2026-10-08T21:17:28.306Z","ecs":{"version":"9.5.0"},
 "event":{"kind":"event","module":"eslabon","dataset":"eslabon.scan","outcome":"success"},
 "package":{"name":"demo-clean","version":"1.0.0"},
 "eslabon":{"schema_version":"1.0","attack_version":"19.2","ecosystem":"npm",
  "scan_id":"5442042935434bf0b2676879adcd4124",
  "archive":{"sha256":"814e497e9b51b73cf0d5b72b725e4cc8f603b67375fec194095a23e09ae41fbe"},
  "scan":{"status":"ok","files_scanned":2,"bytes_read":10240,"findings":0,"anomalies":0,
          "anomaly_kinds":[],"osv_status":"skipped","duration_ms":485},
  "identity_source":"metadata"}}
```

Every field is documented in [`docs/event-schema.md`](docs/event-schema.md) and
enforced by [`schema/event.schema.json`](schema/event.schema.json). To develop: `.venv\Scripts\pip.exe install -e .[dev]`, then
`.venv\Scripts\python.exe -m pytest` and `.venv\Scripts\python.exe -m ruff check .`.
Test fixtures are built in memory at test time ([`tests/builders.py`](tests/builders.py)); no archive is
committed.

To send the events to Wazuh: [`integrations/wazuh/README.md`](integrations/wazuh/README.md) (rules file, agent
`<localfile>` snippet, `wazuh-logtest` samples).

## Rules

The content rules (ESL-001..004) look for combinations rather than a single suspicious
word, but some conditions are enough on their own: a network call in `setup.py` fires
ESL-001, and ESL-005 and ESL-006 judge the name alone. The single source of truth is
[`src/eslabon/catalog.toml`](src/eslabon/catalog.toml); the full conditions and the
known false-positive traps are in [`docs/design.md`](docs/design.md) §5.

| ID | Name | Fires when (summary) | ATT&CK v19.2 | Severity / Wazuh rule, level | Mitigation |
|---|---|---|---|---|---|
| ESL-001 | `pypi-install-exec` | The top-level `setup.py` of a PyPI sdist uses a network primitive, or runs `subprocess`/`os.system` with a download tool or URL | T1546.016, T1059.006 | 8 / 100301, 11 | Prefer wheels (no `setup.py` runs); build sdists only after review, in a sandboxed build (container or VM) with egress blocked |
| ESL-002 | `npm-install-script-exec` | A `preinstall`/`install`/`postinstall` script has a download tool, a pipe to a shell, an inline evaluator (`node -e`, `powershell -enc`) or a URL | T1546.016, T1059.007 | 8 / 100302, 11 | Install with `--ignore-scripts` by default and allow-list the few packages that need lifecycle scripts |
| ESL-003 | `encoded-exec` | An evaluator and a decoder adjacent in the source (Python or JavaScript) | T1027.013, T1140 | 9 / 100303, 12 | Review or reject packages that decode and execute embedded payloads; sandbox first-run of unreviewed dependencies |
| ESL-004 | `secret-exfil` | A credential file path or the whole serialised environment, **and** an exfiltration sink (webhook, paste, tunnel or out-of-band hosts, or a public IPv4 literal URL), in the same file | T1552.001, T1041 | 9 / 100304, 12 | Keep credentials out of build and dev hosts (short-lived tokens, secret managers) and restrict egress to known registries |
| ESL-005 | `typosquat` | The name is not in the bundled top 5,000 and is within edit distance 1 (or a restricted 2) of a top-1,000 name; npm scope confusion | T1195.001 | 5 / 100305, 7 | Pin exact names and hashes in lockfiles; use a private mirror or allow-list of approved packages |
| ESL-006 | `known-malicious` | OSV returns a non-withdrawn `MAL-*` record for this name and version | T1195.001 | 10 / 100306, 13 | Block installs of versions with an OSV MAL advisory (pin + hash-lock dependencies, private mirror with malware screening) |

Each finding also carries the catalog's *residual gap* and *what to detect* next to the
mitigation (`eslabon.mitigation.*`). No Wazuh level 15 is used, on purpose.

**Wazuh maps ESL-003 to T1027 and T1140.** Wazuh 4.14's ATT&CK database has no
T1027.013 (`wazuh-logtest`: `Mitre Technique ID 'T1027.013' not found in database`), so
rule 100303 uses the parent technique (`wazuh_mitre` in `catalog.toml`, ruling R54). The
event itself keeps T1027.013 in `threat.technique.id`.

## Measured false positives

From [`docs/measurements.md`](docs/measurements.md), run on **2026-10-06** with the
scanner at commit **`52d0d8e`** (`src/` unchanged through `13899a9`). The rule code has
not changed since: `git diff 13899a9..HEAD -- src/` touches only event output and catalog
text (where the archive hash is written, the line cap, the ESL-001 mitigation wording
and the Wazuh `<mitre>` override), not the YARA rules, the archive reader,
typosquatting or OSV. The corpus, [`corpus/legit.toml`](corpus/legit.toml), pins
the top 100 PyPI and the top 100 npm packages to exact versions; every package was
downloaded from its registry and scanned with OSV queried.

| ecosystem | packages | fully scanned | incomplete | packages with >=1 false positive |
|---|---|---|---|---|
| pypi | 100 | 95 | 5 | 0 |
| npm | 100 | 99 | 1 | 0 |
| total | 200 | 194 | 6 | 0 |

**0 false positives on 194 of 200 fully scanned packages.** The 6 incomplete scans
(`numpy`, `grpcio`, `ruff`, `scipy`, `lxml`, `@esbuild/linux-x64`) hit Eslabon's own caps
(5,000 members or 10 MiB per member) and give no verdict; they are listed by name in
[`docs/measurements.md`](docs/measurements.md). No rule fired on any package, incomplete ones included.

**Limits.** These are 200 very popular, well-maintained packages, where the content rules
rarely meet a near-miss: ESL-001 was exercised on only 36 `setup.py` files and ESL-002
on about 3 lifecycle scripts. The 0 says little about over-firing on the long tail of
smaller packages. It is measured, not proven. And it is a false-positive count only:
the **detection rate on real malicious packages has not been measured yet**
([roadmap item 1](docs/roadmap.md#1-measuring-detection-against-real-samples)).

ESL-005 cannot fire on that corpus (every corpus name is in its exemption list), so it is
measured separately, by name only, on ranks 5,001-6,000 of each top list:

| ecosystem | FP ranks 5001-6000 | recall on OSV `MAL-` squat names: distance-1 and affix / distance-2 | recall: historical squats |
|---|---|---|---|
| pypi | 14/1000 (1.4%) | 442/455, 14/15 | 6/6 |
| npm | 11/1000 (1.1%) | 90/121, 9/11 | 1/8 |

The 25 known ESL-005 false positives are listed by name in [`docs/measurements.md`](docs/measurements.md). There
is no allowlist: a false positive is fixed in the rule or published, never suppressed by
name.

## Lab result: three layers

Measured on 2026-10-06 ([`docs/evidence/e7/README.md`](docs/evidence/e7/README.md)). Eslabon ran on Kali 2026.2
(Python 3.13.12) with a Wazuh agent `4.14.0-1`, against a manager from the **Wazuh OVA
4.14.0, revision rc2** (ruling R53: the lab VMs of this host, not a 4.14.7 install). Eight
scans of synthetic archives per pass, all with `--offline` except the ESL-006 one, which
queried OSV. Each layer was counted separately,
filtered by the scans' `scan_id`s:

| Layer | Pass 1 (`e660c1e`) | Pass 2 (`7b981f9`) |
|---|---|---|
| Generated (`events.jsonl` on Kali) | 14 | 14 |
| Collected (`archives.json` on the manager) | 14 | 14 |
| Alerted (`alerts.json`) | 14 | 14 |
| Indexed (`wazuh-alerts-*`) | **0** | **14** |

The 14 events: one finding for each of ESL-001..006 (rules 100301..100306, levels 11, 11,
12, 12, 7, 13), seven `ok` summaries (100310) and one `incomplete` summary (100311).
ESL-006 fired live: a synthetic archive declaring `paypalize` 1.0.0 got a `MAL-` advisory
from OSV, and nothing malicious was downloaded. The archives are synthetic: the lab
shows that each rule's alert travels end to end, not how well the rules catch real
malware.

**Why pass 1 indexed 0.** The rules engine alerted on all 14, but the indexer rejected
every alert: the `wazuh-alerts` template maps `data.file` as a keyword, and the events then
carried the archive hash as an object, `file.hash.sha256`. Ruling R54 moved it to
`eslabon.archive.sha256` (a documented deviation from ECS), and pass 2 indexed 14 of 14.

**Line-size experiments.** Lines of 70,000 and 65,300 bytes were dropped silently by the
agent, and of the two small lines written after each, the second was lost too. So the
emitter's line cap is 65,000 bytes. A 65,000-byte line was collected and alerted but not
indexed, because one string in it was over the indexer's 32,766-byte keyword limit;
Eslabon's own strings are capped far below that, and a test pins it. A UTF-8 BOM at the
start of the file is harmless.

**Sigma.** [`integrations/sigma/`](integrations/sigma/MAPPING.md) holds one Sigma rule (ESL-006). No official pySigma
backend for Wazuh exists, so it is translated by hand, and its translation is rule
100306. What is validated end to end is that translation firing in `wazuh-alerts-*`; the
Sigma file itself is not run by any engine.

## What this does not detect

Stated rather than hidden ([`docs/design.md`](docs/design.md) §5,
[`docs/measurements.md`](docs/measurements.md), and the gaps the reviews documented).
Every gap below has its place in [`docs/roadmap.md`](docs/roadmap.md).

**Not measured yet: detection of real malware.** Every rule has fired only on synthetic
fixtures, built at test time and in the lab. How many real malicious packages Eslabon
catches is unknown until
[roadmap item 1](docs/roadmap.md#1-measuring-detection-against-real-samples) is done.

**Per rule:**
- **ESL-001** runs only on the top-level `setup.py` of a PyPI sdist, never on a wheel
  (pip does not run a wheel's `setup.py`). It does **not** look at an in-tree build
  backend: an sdist with no `setup.py` whose `pyproject.toml` points `build-backend` at a
  module shipped in the archive (`backend-path = ["."]`) has that module run at build
  time just as `setup.py` would be, and a network call there gives no finding. It also
  misses a `setup.py` that fetches or runs code through a helper module, and a download
  command assembled indirectly (string formatting, a `shutil.which` lookup) instead of
  written next to the call.
- **ESL-002** does not judge the JavaScript file an install script runs
  (`"postinstall": "node index.js"`), the most common shape of npm malware: the
  legitimate version of that shape (esbuild, sharp, puppeteer) downloads binaries the same
  way. That file is still covered by ESL-003 and ESL-004, which run on every file. Also
  not matched: `node -e "require('./x')"`, `npx <pkg>`, inline code of other interpreters
  (`python -c`, `perl -e`, `bun -e`, `deno eval`), `sh -c` without a download tool or
  URL, shell quoting that splits a word, and node reading code from stdin. The `node -e`
  check emulates no shell, so it may over-fire when a later command in the same script
  has its own `-e` or `-p`.
- **ESL-003** misses multi-stage decoding split across lines, a gap of more than 50
  characters between evaluator and decoder, JavaScript evaluators other than a direct
  `eval`/`Function` call, and Python evaluators reached through aliases or `getattr`.
- **ESL-004** misses exfiltration to an ordinary domain (only known sinks and public IP
  literals count), and environment theft that iterates over the variables instead of
  serialising them all.
- **ESL-005** misses typosquats of packages outside the top 1,000. On npm that costs
  real cases: historical squats of `jquery` (rank 1,888), `cross-env` (1,931) and
  `mongoose` (4,415) are missed (recall 1/8 above). It is a weak signal alone.
- **ESL-006** misses everything nobody has reported yet, and it trusts the declared name
  and version: a renamed or re-versioned known-bad artifact is left to the content rules.

**Archives:**
- A cap (5,000 members, 10 MiB per member, 200 MiB total) **aborts the rest of the
  archive**. Findings before the cap are kept, but the summary says `limits_exceeded`,
  and it must be triaged as an unscanned remainder, never as clean.
- Case-only name collisions, zip local-versus-central name comparison (beyond the
  `BadZipFile` case), tar trailing data, data hidden in tar member padding, and GNU sparse
  content are not analysed.
- `.pth` startup imports, dependency files (`requirements.txt`, `package-lock.json`),
  entropy, metadata signals (package age, missing repository, version jumps),
  steganography and bundled binaries are out of v0.1.

**Wazuh's ATT&CK view.** Wazuh's bundled ATT&CK database is older than the v19.2 the
events carry (the design records it as v13.1; that version number was not checked in the
lab). What the lab showed: Wazuh labels the ESL-003 alert's tactic *Defense Evasion*
where the event says *Stealth*
([`counts-pass2-7b981f9.txt`](docs/evidence/e7/counts-pass2-7b981f9.txt)), and it has
no T1027.013, so the Wazuh rule uses the parent T1027 (`wazuh-logtest` warning in pass 1;
[`integrations/wazuh/README.md`](integrations/wazuh/README.md)). That is the only
substitution found so far.

## Security model

Eslabon processes hostile input. The full threat table, with the test for each row, is
[`docs/design.md`](docs/design.md) §8.

- **Nothing from the package is executed.** No `import`, `subprocess`, `exec` or
  `setup.py` on package content; YARA only reads bytes. ruff's `S` rules police
  Eslabon's own code.
- **Nothing is extracted to disk.** Archives are read in memory, streaming. Traversal,
  absolute and drive paths are recorded as anomalies; symlinks and hardlinks are never
  followed. The only hostile bytes written to disk are a registry download, in a temporary
  directory outside the working tree, deleted after the scan.
- **Caps.** The download (or the local archive) is capped at 50 MiB as stored; inside
  it, bytes actually decompressed are counted: 200 MiB total, 10 MiB per file, 5,000
  members; a zip's declared entry count and directory size are checked before
  parsing. Bombs end as `limits_exceeded`.
- **A wall-clock timeout.** Reading and analysis run in a child process; YARA has a
  per-call timeout and bounded rules. A timeout or a dead worker is never reported as
  clean.
- **Parser differentials.** Paths are normalised the way pip and npm do. A name that
  appears twice is never resolved by "last copy wins": every copy is scanned and
  reported, and the name gets a `duplicate_name` anomaly. Names whose landing place is
  uncertain never supply the package identity.
- **Fail closed.** An unscanned member, a hash mismatch, OSV unavailable or a package with
  no name to check gives exit code 2, never "clean".
- **Network.** HTTPS only: downloads go to an allowlist (`pypi.org`,
  `files.pythonhosted.org`, `registry.npmjs.org`) and OSV queries to `api.osv.dev` only,
  re-checked on every redirect. No credentials are
  needed.
- **Evidence is sanitised.** File names and snippets are attacker-controlled: control
  characters, ANSI escapes, NUL and bidi overrides are stripped, the raw name is kept as
  hex, and every line stays under 65,000 bytes.
- **Synthetic fixtures only.** Tests build their archives at runtime; nothing that looks
  like malware is committed. Suspicious packages are analysed only in the Kali VM.

## v0.1 checklist

The six conditions of [`docs/design.md`](docs/design.md) §1, each with its proof.

- [x] `eslabon scan` analyses a PyPI and an npm package (fixtures) and emits JSON Lines
  that validate against [`schema/event.schema.json`](schema/event.schema.json):
  [`tests/test_cli.py`](tests/test_cli.py) (every emitted event is validated against the
  schema) and [`tests/test_emit.py`](tests/test_emit.py).
- [x] Six heuristics with tests, and the false-positive count on the pinned legitimate
  corpus measured and published. Tests:
  [`test_esl001.py`](tests/test_esl001.py), [`test_esl002.py`](tests/test_esl002.py),
  [`test_esl003.py`](tests/test_esl003.py), [`test_esl004.py`](tests/test_esl004.py),
  [`test_typosquat.py`](tests/test_typosquat.py), [`test_osv.py`](tests/test_osv.py).
  The tests were run red before each rule existed. For ESL-001..004 the red runs are
  recorded in the bodies of commits `ac461f5`, `fea82fe`, `5192cb8` and `b5d917b`; for
  ESL-005 and ESL-006 only in the development ledger, which is not part of this
  repository. The count is in [`docs/measurements.md`](docs/measurements.md) (0 on 194
  of 200).
- [x] Hostile-archive tests (path traversal, links, decompression bombs, hangs) exist and
  pass: [`tests/test_archive_tar.py`](tests/test_archive_tar.py),
  [`tests/test_archive_zip.py`](tests/test_archive_zip.py),
  [`tests/test_worker.py`](tests/test_worker.py).
- [x] End to end in the lab, with the three layers counted separately:
  [`docs/evidence/e7/`](docs/evidence/e7/README.md) (14 = 14 = 14, and 14 indexed, on
  `7b981f9`).
- [x] An English README with *"What this does not detect"*: this file.
- [ ] One lab writeup using the usual template: linked when published.

## Licence

Apache-2.0, the same as eslabon v1. See [`LICENSE`](LICENSE).
