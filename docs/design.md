# Eslabon — design

> Status: draft for approval (2026-10-05). Progress is tracked in stages with exit
> conditions (`E0`…`E8`), never in time.
> A chain is only as strong as its weakest link.

## 1. Purpose and success

Eslabon is a small command-line tool that statically inspects a PyPI or npm package
**without installing or executing it** and emits one JSON Lines event per finding, shaped
for a SIEM (Wazuh 4.14) and mapped to MITRE ATT&CK.

It is built as a portfolio piece for a SOC analyst. It has to be small, finished, and
demonstrated end to end on a real lab, measuring the three coverage layers used in the
companion repository `Proyecto-1`: what the tool **generates**, what the agent **collects**
and what the SIEM **detects**.

**v0.1 is done when, and only when:**

1. `eslabon scan` analyses a PyPI package and an npm package (fixtures) and emits JSON Lines
   that validate against `schema/event.schema.json`.
2. Six heuristics exist, each born from a red test, and the false-positive count on the
   legitimate corpus (top 100 PyPI + top 100 npm, pinned) is measured and published.
   Target: 0.
3. Hostile-archive tests (path traversal, links, decompression bombs, hangs) exist and pass.
4. End to end in the lab: Eslabon runs on Kali with a Wazuh agent, the agent collects the
   JSON, and alerts appear in `wazuh-alerts-*`. The three layers are counted separately.
5. An English README that a stranger understands in two minutes, including
   *"What this does not detect"*.
6. One writeup in `../02-writeups/` using the usual template.

Anything not needed for this list goes to `docs/roadmap.md` and is not built in v0.1.

## 2. Positioning (prior art)

| Tool | What it does | Gap Eslabon targets |
|---|---|---|
| DataDog GuardDog (Apache-2.0) | Code and metadata heuristics on 7 ecosystems. In 3.0 (2026-06-26) it moved from Semgrep to YARA and added a 0–10 risk score. It scans inside a kernel sandbox | Output is JSON or SARIF. No ATT&CK technique mapping. Its only SIEM path is Datadog's own |
| OSV-Scanner (Google) | Matches lockfiles against known advisories | Sees only what has already been reported |
| Packj (AGPL-3.0) | Static, metadata and **dynamic** (strace) analysis | Executes what it analyses |
| Socket (SaaS) | Commercial, 70+ risk types | Closed source; SIEM integration only on paid tiers |
| deps.dev (Google) | Metadata API | Enrichment, not detection |

**Eslabon does not out-detect GuardDog, and the README says so.** Its contribution is the
detection turned into a triageable SIEM alert: ECS-shaped, ATT&CK-mapped, evidence included,
mitigation included, and validated end to end on a free SIEM.

No GuardDog rule is copied. If one is ever adapted, Apache-2.0 §4 applies: keep its header,
mark the changes, and carry its NOTICE into `NOTICE`.

Sources: <https://securitylabs.datadoghq.com/articles/guarddog-3-0-release/>,
<https://github.com/DataDog/guarddog>, <https://github.com/google/osv-scanner>,
<https://github.com/ossillate-inc/packj>, <https://socket.dev/pricing>,
<https://docs.deps.dev/api/v3/>.

## 3. Scope

**In v0.1**
- Ecosystems: PyPI and npm.
- Inputs: a local archive (`.tar.gz`, `.tgz`, `.tar.bz2`, `.zip`, `.whl`) and `name==version`
  fetched directly from the registry over HTTPS.
- Heuristics ESL-001 to ESL-006 (§5).
- Output: JSON Lines (§6). Wazuh rules, one Sigma rule and its hand translation (§7).

**Out (roadmap, H8)**: listed in order of priority.
1. Measuring detection against real samples (DataDog's malicious-packages dataset), only
   inside Kali, with a snapshot before and a restore after.
2. `.pth` files that `import` at interpreter startup.
3. Archive anomalies beyond v0.1: case-only name collisions, zip local/central name
   comparison, tar trailing data.
4. Dependency files (`requirements.txt`, `package-lock.json`).
5. Entropy, metadata signals (package age, missing repository, odd version jumps),
   steganography, bundled binaries.
6. Syslog/CEF output; publishing to PyPI (the name `eslabon` was free on PyPI and npm on
   2026-10-05).

## 4. Architecture

```
eslabon scan <archive | name==version> --ecosystem {pypi,npm} [--out FILE] [--offline]

cli ─► fetch ─► [worker process, wall-clock timeout]
                 archive (streaming, capped) ─► analyzers ─► findings
                                                ├ yara_engine + rules/*.yar   ESL-001..004
                                                ├ typosquat                   ESL-005
                                                └ osv                         ESL-006
    ─► emit ─► events.jsonl ─► Wazuh agent (localfile, log_format json)

catalog.toml: the single source of truth for every rule
```

| Module | Responsibility |
|---|---|
| `cli.py` | Parses arguments, runs one scan, sets the exit code: `0` clean, `1` findings, `2` error or incomplete scan. **`2` wins over `1`**: if a scan has findings *and* is incomplete, the findings are still emitted and the exit code is `2`. `--ecosystem` is inferred only for `.whl` (PyPI); otherwise it is required |
| `fetch.py` | Resolves the artifact URL from the registry API and downloads it with `urllib`. See the list below |
| `archive.py` | Reads the archive **in memory, streaming, never extracting to disk** (§8). Yields `(path, bytes)` for regular files plus a list of anomalies |
| `worker.py` | Runs archive reading and analysis in a child process (`multiprocessing`, spawn) with a wall-clock timeout. The parent reads the result queue with `q.get(timeout=…)` **before** `join()` (joining a child with unflushed queue data deadlocks), then `terminate()`s on timeout. The child target is a top-level function. A timeout produces `status=timeout`, exit 2, never "clean" |
| `yara_engine.py` | Compiles `rules/*.yar` with `error_on_warning=True`, matches each file's bytes with a per-call `timeout`, and turns matches into findings with file, line and snippet |
| `typosquat.py` | Normalises the name and compares it with a bundled top-packages snapshot using its own Damerau-Levenshtein distance |
| `osv.py` | Queries `POST https://api.osv.dev/v1/query` and keeps only non-withdrawn `MAL-*` records |
| `catalog.toml` | Per rule: id, name, severity, ATT&CK techniques and tactics, Wazuh level, and *mitigation → residual gap → what to detect* |
| `emit.py` | Builds the events, sanitises attacker-controlled strings, caps the snippet at 1 KB, and writes UTF-8 **without BOM**, one object per line |

`fetch.py` in detail:
- **PyPI:** reads `https://pypi.org/pypi/<name>/<version>/json` and prefers the sdist,
  because `setup.py` lives there. Without an sdist it takes the `py3-none-any` wheel, then
  the first `cp313` manylinux x86_64 wheel, then the first wheel listed. It verifies
  `digests.sha256`.
- **npm:** reads `https://registry.npmjs.org/<name>/<version>`, with the `/` of a scoped
  name encoded as `%2f`, and verifies `dist.integrity` (sha512). Old versions that publish
  only a sha1 `shasum` are accepted, verified against it, and recorded as the anomaly
  `weak_hash_sha1`.
- **Hosts and redirects:** only `https` to an allowlist (`pypi.org`,
  `files.pythonhosted.org`, `registry.npmjs.org`). A custom redirect handler re-checks the
  allowlist and the scheme on every hop.
- **Download limits:** bytes are counted as they arrive, never trusting `Content-Length`,
  and the socket has a timeout.
- **Hash mismatch:** `status=hash_mismatch`, exit 2.

Runtime dependency: **`yara-python` only**. Network uses `urllib`, configuration uses
`tomllib` and the distance function is our own. Every dependency is supply-chain surface;
a supply-chain tool should not bring twenty.

Python: **3.13** on both the host and Kali. On 3.12, CVE-2025-8194 (an infinite loop
while iterating a crafted tar) is fixed only in source-only releases, so Windows hosts
cannot get it. Wheels for `yara-python` 4.5.4 exist for cp313 on win_amd64 and manylinux
x86_64, and there are no cp314 wheels.

## 5. Heuristics

All six are **compound** signals: one indicator alone is never enough. The known
false-positive traps listed below each come from real popular packages and become
near-miss test fixtures.

| ID | Name | Fires when | Must NOT fire on | ATT&CK (v19.2) | Severity / Wazuh level |
|---|---|---|---|---|---|
| ESL-001 | `pypi-install-exec` | `setup.py` contains a network primitive (`urlopen`, `urllib.request`, `requests.get/post`, `socket.socket`, `http.client`), **or** a `subprocess`/`os.system` call whose arguments carry a download tool or URL (`curl`, `wget`, `powershell`, `http`) | `exec(open('…/version.py').read())` (requests-style version loading); `subprocess` to build tools such as `pg_config`/`xslt-config` (psycopg2, lxml) | T1546.016, T1059.006 | 8 / 11 |
| ESL-002 | `npm-install-script-exec` | A `preinstall`/`install`/`postinstall` script in `package.json` contains a download tool, a pipe to a shell, an inline evaluator (`node -e`, `powershell -enc`) or a URL | `node install.js` (esbuild, puppeteer, sharp), `node-gyp rebuild`, `husky install` | T1546.016, T1059.007 | 8 / 11 |
| ESL-003 | `encoded-exec` | A decoder and an evaluator **adjacent** in the source (bounded regex, ≤ 50 chars): `exec/eval/compile` with `b64decode/decodebytes/bytes.fromhex/zlib.decompress`; `eval/Function` with `atob`/`Buffer.from(…,'base64')` | Base64 used for data (images, test vectors) with no evaluator next to it | T1027.013, T1140 | 9 / 12 |
| ESL-004 | `secret-exfil` | A credential source (`.ssh/id_`, `.aws/credentials`, `.npmrc`, `.pypirc`, `.git-credentials`, or the **whole** environment serialised: `JSON\.stringify\(\s*process\.env\s*\)`, `json\.dumps\(\s*(dict\()?os\.environ`) **and** an exfiltration sink (`discord(app)?\.com/api/webhooks`, `api\.telegram\.org/bot`, `hooks\.slack\.com`, `pastebin\.com`, `ngrok(-free)?\.(io|app)`, `oast\.(fun|pro|live|site|online|me)`, `interact\.sh`, `burpcollaborator\.net`, or an `http(s)://` URL with a **public** IPv4 literal — loopback, RFC 1918, link-local incl. `169.254.169.254` and `0.0.0.0` excluded) in the same file | botocore and google-auth (credential files + IMDS `169.254.169.254`); requests/urllib3/axios (proxy variables + HTTP); `JSON.stringify(process.env.NODE_ENV)` in every webpack bundle; `dict(os.environ)` passed to a subprocess; `toast` libraries (substring `oast`) | T1552.001, T1041 | 9 / 12 |
| ESL-005 | `typosquat` | The **full** name (with npm scope) is not in the bundled top-5,000 list, and after normalisation (PEP 503 for PyPI; scope stripped for npm) it is within Damerau-Levenshtein distance 1 (names of 5 characters or fewer) or 2 (longer names) of a top-1,000 package. Distance **0** after stripping a scope (`@evil/react`) is reported as scope confusion under the same rule | Any full name in the top-5,000 list (`ms`/`qs`/`ws`, `chalk`/`chai`, `numpy`/`numba`, `boto`/`boto3`, `@babel/core`) | T1195.001 | 5 / 7 |
| ESL-006 | `known-malicious` | OSV returns a non-withdrawn `MAL-*` record for this name and version | CVE/GHSA/PYSEC records, which the same API returns mixed in | T1195.001 | 10 / 13 |

**Finding granularity:** one finding per (rule, file). The evidence is taken from the first
match. `eslabon.evidence.match_count` records how many matches there were. This is the unit
counted as N in the lab measurement.

**Snippet window:** decoded text from 120 bytes before to 200 bytes after the match offset,
capped at 1 KB. `line` is the number of `\n` before the offset, plus one. In minified
single-line files, `line` is therefore 1, and the snippet is what locates the match.

**Top-package lists:**
- PyPI: a dated snapshot of `hugovk/top-pypi-packages`.
- npm: a dated snapshot of the source chosen and verified in E4, with `npm-high-impact` as
  the candidate.

Both are committed with their date and URL.

**Residual gaps, stated rather than hidden.** These go into the README:
- ESL-002 does not judge the JavaScript file that an install script runs
  (`"postinstall": "node index.js"`), which is the most common shape of npm malware. The
  legitimate version of that exact shape (esbuild, sharp, puppeteer) downloads binaries with
  `child_process` and `https`, so a network-plus-exec rule on that file would not tell them
  apart. That file is still covered by ESL-003 and ESL-004, which run on every file.
- ESL-004 misses exfiltration to an ordinary domain.
- ESL-003 misses multi-stage decoding split across lines.
- ESL-005 misses typosquats of packages outside the top 1,000.
- ESL-006 misses everything nobody has reported yet.

Engine: YARA for ESL-001, ESL-003 and ESL-004, applied to file bytes. ESL-002 parses
`package.json` with `json` and applies a YARA rule to the script strings. Typosquatting and
OSV are plain Python.

No Wazuh level 15 is used, deliberately. In `Proyecto-1` a level 15 that fired 60 times on
benign activity taught the analyst to ignore level 15.

## 6. Event schema

Contract: `docs/event-schema.md` explains every field and `schema/event.schema.json`
enforces it. Every emitted line is validated in tests. A change of meaning bumps
`eslabon.schema_version`.

**Finding** (`event.kind: alert`, `event.dataset: eslabon.finding`):

```json
{"@timestamp":"2026-10-05T18:00:00.000Z",
 "ecs":{"version":"<ECS reference used to write event-schema.md>"},
 "event":{"kind":"alert","category":["package","malware"],"type":["info"],
          "module":"eslabon","dataset":"eslabon.finding","severity":9},
 "rule":{"id":"ESL-003","name":"encoded-exec","ruleset":"eslabon","version":"0.1.0"},
 "threat":{"framework":"MITRE ATT&CK",
           "technique":{"id":["T1027.013","T1140"],"name":["Encrypted/Encoded File","Deobfuscate/Decode Files or Information"]},
           "tactic":{"id":["TA0005"],"name":["Stealth"]}},
 "package":{"name":"reqeusts","version":"1.0.0"},
 "file":{"hash":{"sha256":"…"}},
 "eslabon":{"schema_version":"1.0","attack_version":"19.2","ecosystem":"pypi","scan_id":"…",
   "evidence":{"file":"setup.py","line":14,"snippet":"exec(<decoded payload>)","name_hex":"…"},
   "mitigation":{"action":"…","residual_gap":"…","detect":"…"}}}
```

- `ecs.version` holds the exact ECS release whose field reference `docs/event-schema.md` was
  written against. Recording it is part of E2's exit condition.
- `file.*` describes the **downloaded or supplied archive**, not the inner file that
  matched. That inner file is `eslabon.evidence.file`.
- `package.type` and `package.checksum` are **not** used. In ECS they mean the package file
  type and the hash of the installed package. The ecosystem goes in `eslabon.ecosystem` and
  the artifact hash in `file.hash.sha256`/`sha512`.
- Every emitted path is capped at 512 characters and every hex field at 1,024 characters.
  A pax header can make a member name megabytes long.
- For a local archive, `package.name` and `package.version` are read from inside it (sdist
  `PKG-INFO`, wheel `METADATA`, npm `package.json`). They are attacker-controlled. If they
  are absent, the anomaly `no_metadata` is recorded and ESL-005 and ESL-006 are skipped.
- Arrays hold strings only. The Wazuh JSON decoder keeps string arrays but does not support
  arrays of objects.

**Scan summary** (`event.kind: event`, `event.dataset: eslabon.scan`): one per scan.
- `event.outcome`: `success` or `failure`.
- `eslabon.scan.status`: `ok`, `timeout`, `limits_exceeded`, `parse_error`,
  `hash_mismatch`, `fetch_error` or `osv_unavailable`.
- `eslabon.scan.files_scanned`, `bytes_read`, `findings`, `anomalies` and `duration_ms`.

Without the summary, "zero findings" and "nothing arrived" look identical in the SIEM. With
it, the generate layer can be measured by counting.

**OSV unavailable** gives `status=osv_unavailable` and exit 2: "clean" must mean fully
checked. `--offline` skips OSV explicitly and records `osv_status=skipped`.

## 7. Integrations

**Wazuh** (`integrations/wazuh/`):
- `local_rules.xml`, installed on the manager as its own file,
  `/var/ossec/etc/rules/eslabon_v2_rules.xml`, so v1's rules are never edited. IDs
  **100300–100399**, group **`eslabon_v2`**. Wazuh produces **one alert per event**, so the
  rule tree is built so that each event reaches exactly one leaf rule. No custom decoder: the
  built-in `json` decoder handles lines that start with `{"`.
  - **Coexistence with eslabon v1.** The lab manager already runs the earlier eslabon, an
    orchestrator of external scanners, with rule IDs 100100–100170, group `eslabon`, and a
    base rule limited to `<location>eventos.jsonl$</location>`. This range, this group and
    this log path (`events.jsonl`) were chosen so the two never collide.
  - `100300` is the parent rule: `<decoded_as>json</decoded_as>` +
    `<location>events.jsonl$</location>` + `<field name="event.module">^eslabon$</field>`,
    level 0. Limiting it to its own file is the practice v1 validated in the lab.
  - `100301`–`100306` are one child per ESL rule, each with its `<mitre>` IDs and the level
    from `catalog.toml`.
  - `100310` is the scan summary with status `ok`, at level 3, the lowest level that is
    indexed, so it can be counted.
  - `100311` is the scan summary with any other status, at level 7.
  - `100306` is also the hand translation of the Sigma rule (see below). No separate Sigma
    rule exists, because it would compete with `100301`–`100306` for the same events.
- `agent-ossec.conf.snippet`: a `<localfile>` for `/var/log/eslabon/events.jsonl` with
  `log_format json`. Kali's agent configuration is trimmed to this block so that Kali's own
  noise does not pollute the measurement.
- `logtest-samples/`: one line per rule, with the expected `wazuh-logtest` phase-3 output.
- A test asserts that the levels and `<mitre>` IDs in the XML match `catalog.toml`.

**Wazuh's ATT&CK database is v13.1** (since 4.8), so the dashboard shows older names, e.g.
*Defense Evasion* for TA0005. Events carry v19.2 names. Each `<mitre>` ID is checked in
`wazuh-logtest` for "not found" warnings. If a sub-technique is missing from Wazuh's
database, its parent is used in the XML and the README says so.

**Sigma** (`integrations/sigma/`): one rule, *"Known-malicious package (Eslabon ESL-006)"*.
It has its own `logsource` (`product: eslabon`) and matches `event.module: eslabon`,
`event.dataset: eslabon.finding` and `rule.id: ESL-006`.
- It was originally *"severity ≥ 7"*. It changed because Wazuh produces one alert per event,
  so a separate severity rule would have competed with the per-heuristic rules for the same
  events. Either the severity alert or the per-rule ATT&CK alert would never have been seen.
- No official pySigma backend for Wazuh exists
  (<https://github.com/wazuh/wazuh/issues/17568>), so the rule is **translated by hand**, and
  its translation is rule `100306`. A field mapping table sits next to it. What is validated end to end is that
translation firing in `wazuh-alerts-*`, and the README says exactly that.

## 8. Security model

Eslabon processes hostile input. The rules below are not negotiable.

| Threat | Defence | Test |
|---|---|---|
| Executing package code | Never `import`, `subprocess`, `exec` or `setup.py` on package content; YARA only reads bytes. Our own code is policed by ruff's `S` rules (S102, S307, S404, S603, S301, S506) | ruff in the test run |
| Path traversal, absolute or drive paths | **Nothing is written to disk.** The name is recorded as an anomaly | A `../` member creates no file; the anomaly is in the summary |
| Symlinks and hardlinks | Never followed; counted toward the member cap and the anomaly count | A link to `/etc/passwd` is not read |
| Decompression bomb, huge pax/GNU headers | gzip/bz2 are opened by our code, wrapped in a counting reader, and read with `tarfile.open(fileobj=…, mode="r|")` (streaming). Caps on **bytes actually decompressed**: 50 MB download, 200 MB total, 10 MB per file, 5,000 members | Gzip bomb and pax-header bomb both give `limits_exceeded` |
| Zip central-directory exhaustion | The EOCD / ZIP64 EOCD entry count and directory size are read with `struct` **before** `ZipFile`. Reject above 5,000 entries, or a directory larger than 5,000 × (46 + 512) bytes ≈ 2.8 MB, a cap derived from the member cap | A zip declaring 1,000,000 entries is rejected before parsing |
| Parser exceptions | Caught **per member** and recorded as anomalies, not crashes: `BadZipFile` (local-header and central-directory names differ), `RuntimeError` (encrypted member), `NotImplementedError` (e.g. Deflate64). Non-zero trailing data after a gzip stream ends the scan with `status=parse_error` | Each exception class has a fixture |
| CPU hangs (CVE-2025-8194-style loops, slow streams, regex blow-up) | Child process with wall-clock timeout; YARA `timeout=`; rules compiled with `error_on_warning=True` and bounded `.{0,N}` | A fake analyser that sleeps gives `status=timeout` |
| Peak memory | Each tar member is scanned as soon as it is read, then dropped (peak ≈ 10 MB). A zip must be held whole for `ZipFile`, so the zip peak is ≈ 60 MB (50 MB archive + one 10 MB member) | Covered by the bomb tests |
| Parser differentials | Paths are normalised the way npm and pip do (`\` → `/`, `./` and `//` collapsed, npm's first component stripped). Duplicate names are an anomaly, and every copy is scanned and reported. Case-only collisions, zip local/central name comparison beyond the exception above, and tar trailing-data detection are on the roadmap | Duplicate `package/package.json` is flagged and every copy is scanned |
| Redirect and host tricks | Allowlisted hosts, `https` only, re-checked on every redirect | A redirect to another host or to `http` is rejected |
| Injection through evidence | File names and snippets are attacker-controlled. C0/C1 controls, ANSI escapes, NUL and bidi overrides (U+202A–202E, U+2066–2069) are stripped; text is decoded with `errors="replace"` before truncating; the raw name is kept in `name_hex` | A name containing `\n`, `\x1b[` and U+202E comes out clean |

Operational rules:
- **Synthetic fixtures are built at test runtime** in a temporary directory. No file that
  looks like malware is committed. This keeps GitHub and the host's Defender quiet and
  matches the `.gitignore`.
- **Suspicious packages are analysed only in Kali.** The host runs the test suite and the
  legitimate corpus only.
- The pytest configuration pins `testpaths = ["tests"]` so that no collected path can ever
  contain package content.
- No secrets are needed: OSV and both registries are queried without authentication.

## 9. Testing and measurement

**Unit tests (TDD, no network, nothing executed):**
- Every heuristic has a positive fixture and a near-miss fixture built from §5's
  "must not fire" column. Each test is seen red before it is made green.
- Hostile-archive tests cover every row of §8.
- Every emitted line validates against the JSON Schema and is shorter than 64 KB.
- Consistency: every catalog rule has an implementation; the Wazuh XML matches the catalog.
- OSV and registry clients are tested against recorded responses. One opt-in test marked
  `@pytest.mark.network` talks to the real APIs.

**False-positive measurement:**
- `corpus/legit.toml` pins the top 100 PyPI packages (a dated snapshot of
  `top-pypi-packages`) and the top 100 npm packages, each with an exact version.
- `scripts/measure_fp.py` scans all 200 packages from the registries. Its table has three
  columns, **fully scanned / incomplete / false positives**. An incomplete scan (e.g. a
  large sdist hitting a cap) gives no verdict, so the README states the claim as "N false
  positives on X of 200 fully scanned", with the incomplete packages listed by name.
- ESL-005 cannot produce a false positive on that corpus, because every corpus package is
  in its own exemption list. Its false-positive rate is therefore measured separately and by
  name only (no download): every name ranked 5,001–6,000 in each ecosystem's list.
- **No package-name allowlists.** A false positive is fixed in the rule or published as a
  known false positive; suppressing a popular name to hit "0" would be gaming the metric.
- The npm list's source is chosen and recorded in E4, because ESL-005 needs it there. The
  candidate is `npm-high-impact`, to be verified before use.

**Lab measurement (E7):** three layers, counted separately.

| Layer | What is counted | Where |
|---|---|---|
| Generate | Lines in `events.jsonl`, per `rule.id` | Kali |
| Collect | Events received by the manager, whether or not a rule fires | `<logall_json>yes</logall_json>`, enabled only for the session, counted in `archives.json` |
| Detect | Alerts per `rule.id` in `wazuh-alerts-*` | The dashboard console-proxy query |

- **Expected:** N = N = N, and any difference is explained.
- **One deliberate experiment:** emit a 70 KB line and record what each layer does with it.
  The emitter cannot produce such a line, because of the 64 KB test, so the line is written
  by a separate script, `scripts/oversize_line.py`.
  This confirms with our own data the logcollector line limit (65279 bytes) and the warning
  it logs, which is the reason for the 1 KB snippet cap.

## 10. Stages

| Stage | Builds | Exit condition (shown by command output) |
|---|---|---|
| E0 Base | Python 3.13 on the host (installed by the user), venv, `pyproject.toml`, ruff with `S` rules, pytest, `catalog.toml` | `pytest` and `ruff check` green. The first commit contains no ignored file |
| E1 Hostile reading | `archive.py`, `worker.py` | All §8 tests green, including the hang test. `security-review` has no open finding |
| E2 Event | Schema, `emit.py`, summary event, CLI on a local archive | `eslabon scan fixture.tgz` emits a summary that validates; the line-length test is green; `ecs.version` is recorded |
| E3 Code heuristics | ESL-001…004 | 4 × (positive + near-miss) green, each seen red first |
| E4 Context and reputation | ESL-005, ESL-006, `fetch.py` | Tests green; `eslabon scan requests==<pinned>` against the real registry ends with the hash verified |
| E5 False positives | Corpus, `measure_fp.py`, ESL-005 name-only check | Table of fully scanned / incomplete / FP measured; every false positive either fixed in its rule or published; ESL-005 rate on ranks 5,001–6,000 measured. Target 0 |
| E6 Offline integration | Wazuh XML, Sigma and its translation, logtest samples, agent snippet | Consistency tests green |
| E7 Lab end to end | Kali snapshot, trimmed agent, Eslabon on Kali, logtest on the manager, three-layer count, 70 KB experiment | N = N = N (or explained), with the queries and their output saved as evidence; Kali restored |
| E8 Publish | README with *"What this does not detect"*, `simplify`, `code-review`, `docs/roadmap.md`, writeup | All six items of §1 ticked, each linked to its proof |

E0–E6 need no lab. E7 is the lab session and gets its writeup.

## 11. Things to verify, not assume

Each of these is checked in the stage named and recorded with its result:

| Check | Stage |
|---|---|
| The alert stores our fields as `data.rule.*`, separate from Wazuh's own `rule.*` | E7, `wazuh-logtest` |
| How a `<field>` matches against a string array (`threat.technique.id`) | E7 |
| `$(rule.name)` and `$(package.name)` interpolate in rule descriptions | E7 |
| `T1027.013` and `T1546.016` exist in Wazuh's v13.1 ATT&CK database | E7 |
| What a 70 KB line and a UTF-8 BOM do at each layer | E7 |
| Kali's `python3` version: 3.14 has no `yara-python` wheel | E7 |

## 12. References

- ATT&CK v19.2: <https://attack.mitre.org/resources/versions/>,
  <https://attack.mitre.org/techniques/T1195/001/>
- OSV API: <https://google.github.io/osv.dev/api/>; malicious-packages feed:
  <https://github.com/ossf/malicious-packages>
- Wazuh 4.14:
  - JSON decoder: <https://documentation.wazuh.com/4.14/user-manual/ruleset/decoders/json-decoder.html>
  - localfile: <https://documentation.wazuh.com/4.14/user-manual/reference/ossec-conf/localfile.html>
  - logtest: <https://documentation.wazuh.com/4.14/user-manual/reference/tools/wazuh-logtest.html>
- ECS: <https://www.elastic.co/guide/en/ecs/current/ecs-package.html>
- CPython tar CVEs: <https://nvd.nist.gov/vuln/detail/cve-2025-8194>
