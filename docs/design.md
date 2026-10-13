# Eslabon — design

> Status: the design v0.1 was built to (written 2026-10-05). What is not built is in
> `docs/roadmap.md`; what v0.1 misses is in the README's *"What this does not detect"*.
> Progress was tracked in stages with exit conditions (§10), never in time.
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
6. One writeup using the usual template. It is written and kept in the author's portfolio, outside this
   repository, and is not published yet.

Anything not needed for this list goes to `docs/roadmap.md` and is not built in v0.1.

## 2. Positioning (prior art)

| Tool | What it does | Gap Eslabon targets |
|---|---|---|
| DataDog GuardDog (Apache-2.0) | Code and metadata heuristics on 7 ecosystems (Rust added in 3.2.0). 3.0.0 (2026-06-23) moved from Semgrep to YARA and added a 0–10 risk score. Extraction and scanning run in a sandbox (nono) that protects the host; no package code is executed. Version 3 also flags URL dependencies and a version that adds install scripts, which Eslabon does not check. Like Eslabon, it scans one archive per PyPI version (checked 2026-10-12) | Output is JSON or SARIF (SARIF only for `verify`). ATT&CK tactics on threat findings, no technique IDs; T1195 is added by Datadog Cloud SIEM rules, its only official SIEM integration |
| OSV-Scanner (Google) | Matches lockfiles against known advisories, including OSV `MAL-*` records, transitive dependencies included | Sees only what has already been reported |
| Packj (AGPL-3.0) | Static and metadata analysis by default; an optional dynamic mode (strace) (checked 2026-10-12) | Its dynamic mode executes the package it analyses |
| malcontent (Chainguard, Apache-2.0) | YARA (14,500+ rules) and a diff between two versions of a package (checked 2026-10-12) | No ATT&CK or SIEM output |
| Socket (SaaS) | Commercial, 70+ risk types | Closed source; no SIEM integration on the Free plan |
| deps.dev (Google) | Metadata API | Enrichment, not detection |

Install-time firewalls (Socket Firewall Free, Aikido Safe Chain, Datadog Supply-Chain
Firewall, Veracode Package Firewall, JFrog Curation, Sonatype Repository Firewall) block
known malware before or during download; Eslabon does not block, it detects and alerts
after download. OSV-Scanner applies the same OSV `MAL-*` data as ESL-006, but to a whole
lockfile including transitive dependencies; for a full dependency tree, use it.

**Eslabon does not out-detect GuardDog, and the README says so.** Its contribution is the
detection turned into a triageable SIEM alert: ECS-shaped, mapped to ATT&CK techniques,
evidence included, mitigation and residual gap included, and validated end to end on a free
SIEM. None of the tools above emits that into Wazuh.

No GuardDog rule is copied. If one is ever adapted, Apache-2.0 §4 applies: keep its header,
mark the changes, and carry its NOTICE into `NOTICE`.

Sources (checked 2026-10-12):
- GuardDog: <https://securitylabs.datadoghq.com/articles/guarddog-3-0-release/>,
  <https://github.com/DataDog/guarddog/tree/v3> (README, `guarddog/analyzer/risk_engine.py`,
  `guarddog/analyzer/metadata/npm/`), <https://pypi.org/project/guarddog/> (release dates),
  <https://docs.datadoghq.com/security/default_rules/def-000-yb1/> (Datadog Cloud SIEM, T1195).
- OSV-Scanner: <https://github.com/google/osv-scanner>,
  <https://google.github.io/osv-scanner/supported-languages-and-lockfiles/>.
- Packj: <https://github.com/ossillate-inc/packj>.
- malcontent: <https://github.com/chainguard-dev/malcontent>.
- Socket: <https://socket.dev/pricing>, <https://docs.socket.dev/docs/socket-firewall-free>.
- Firewalls: <https://github.com/AikidoSec/safe-chain>,
  <https://github.com/DataDog/supply-chain-firewall>, <https://docs.socket.dev/>,
  <https://www.veracode.com/>, <https://docs.jfrog.com/>, <https://www.sonatype.com/>.
- deps.dev: <https://docs.deps.dev/api/v3/>.

## 3. Scope

**In v0.1**
- Ecosystems: PyPI and npm.
- Inputs: a local archive (`.tar.gz`, `.tgz`, `.tar.bz2`, `.zip`, `.whl`) and `name==version`
  fetched directly from the registry over HTTPS.
- Heuristics ESL-001 to ESL-006 (§5).
- Output: JSON Lines (§6). Wazuh rules, one Sigma rule and its hand translation (§7).

**Out (roadmap)**: listed in order of priority.
1. Measuring detection against real samples (DataDog's malicious-packages dataset), only
   inside Kali, with a snapshot before and a restore after.
2. Code that runs on import or at interpreter startup: a wheel's module-level
   `__init__.py`, the `import` lines of `.pth` files and Python 3.15 `.start` files.
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
  `digests.sha256`. pip itself installs a compatible wheel before an sdist, so when both
  exist the artifact scanned is not the one pip would install; to judge that wheel, scan it
  as a local file.
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
| ESL-003 | `encoded-exec` | A decoder and an evaluator **adjacent** in the source: the evaluator, up to 10 whitespace characters (line breaks included) before its `(`, then one optional line break (`\r?\n`) right after the `(`, then at most 50 characters that are not line breaks, then the decoder. Python: `exec`/`eval`/`compile` (not preceded by `.` or a word character) with `b16decode`/`b32decode`/`b64decode`/`b85decode`, `a85decode`, `decodebytes`, `a2b_base64`, `unhexlify`, `bytes.fromhex`, `zlib`/`lzma`/`bz2`/`gzip` `.decompress` or `codecs.decode`. JavaScript: `eval`/`Function` with `atob(` or `Buffer.from(` (any encoding) | Base64 used for data (images, test vectors) with no evaluator next to it; methods and longer names such as `re.compile(`, `model.eval(`, `literal_eval(` | T1027.013, T1140 | 9 / 12 |
| ESL-004 | `secret-exfil` | A credential source (a path `\.ssh[/\\]id_(rsa|ed25519|ecdsa|dsa)`, `\.aws[/\\]credentials`, `.npmrc`, `.pypirc`, `.git-credentials`, `\.docker[/\\]config\.json`, `\.kube[/\\]config`, the separator being `/` or one or two backslashes; the same files as quoted path segments, `['"]\.ssh['"]\s*[,/]\s*['"]id_(rsa|...)` and `['"]\.aws['"]\s*[,/]\s*['"]credentials`, as in `path.join` or pathlib; these file patterns are case-insensitive; or the **whole** environment serialised, case-sensitive: `JSON\.stringify\(\s*(\{\s*\.\.\.\s*|Object\.entries\(\s*|Object\.assign\(\s*\{\s*\}\s*,\s*)?process\.env\s*[)},]`, `json\.dumps\(\s*(dict\(\s*)?os\.environ`, `json\.dumps\(\s*\{\s*\*\*\s*os\.environ\s*[},]`, `str\(\s*os\.environ\s*\)`; all bounded, `\s*` is `\s{0,10}`) **and** an exfiltration sink, case-insensitive (`discord(app)?\.com/api/webhooks`, `api\.telegram\.org/bot`, `hooks\.slack\.com`, `pastebin\.com`, `ngrok(-free)?\.(io|app)\b`, `oast\.(fun|pro|live|site|online|me)\b` and `interact\.sh\b`, these two not preceded by a word character or `-`, `burpcollaborator\.net`, `webhook\.site\b`, `requestbin\.(com|net|io|org|fullcontact\.com)\b`, `pipedream\.net`, or an `http(s)://` URL with an IPv4 literal that is **public**: checked in Python with `ipaddress` `is_global` under the decimal and the octal (leading zero) reading of each octet, and kept if any reading is global; loopback, RFC 1918, link-local incl. `169.254.169.254`, `0.0.0.0`, CGNAT, documentation and reserved ranges, and octets above 255, are excluded; if no sink survives, there is no finding) in the same file, on any member of either ecosystem | botocore and google-auth (credential files + IMDS `169.254.169.254`); requests/urllib3/axios (proxy variables + HTTP); `JSON.stringify(process.env.NODE_ENV)` in every webpack bundle; `dict(os.environ)`, bare `{...process.env}` / `{**os.environ}` and `Object.entries(process.env)` iteration, which copy the environment for a child process; `toast` libraries (substring `oast`) | T1552.001, T1041 | 9 / 12 |
| ESL-005 | `typosquat` | The **full** name (with npm scope) is not in the bundled top-5,000 list. **Unscoped** names: normalised (PEP 503 for PyPI; lowercase for npm), at least 4 characters, and within Damerau-Levenshtein (OSA) distance 1 of an **unscoped** top-1,000 name; distance 2 counts only for names of 6+ characters whose first character matches the target and whose two edits are insertions, deletions or transpositions (no substitution). Trailing digits are not ignored (`urllib33`). **npm scoped** names: skipped when the scope owns any top-5,000 name; otherwise reported only as scope confusion when the bare name equals an unscoped top-1,000 name (`@evil/react`). A scoped target's bare name is never compared. Measured in docs/measurements.md | Any full name in the top-5,000 list (`ms`/`qs`/`ws`, `chalk`/`chai`, `numpy`/`numba`, `boto`/`boto3`, `@babel/core`); names shorter than 4; names in an owned scope (`@types/...`) | T1195.001 | 5 / 7 |
| ESL-006 | `known-malicious` | OSV returns a non-withdrawn `MAL-*` record for this name and version | CVE/GHSA/PYSEC records, which the same API returns mixed in | T1195.001 | 10 / 13 |

**Finding granularity:** one finding per (rule, file). The evidence is taken from the first
match. `eslabon.evidence.match_count` records how many matches there were. This is the unit
counted as N in the lab measurement.

**Snippet window:** decoded text from 120 bytes before to 200 bytes after the match offset,
capped at 1 KB. `line` is the number of `\n` before the offset, plus one. In minified
single-line files, `line` is therefore 1, and the snippet is what locates the match.

**Top-package lists:**
- PyPI: a dated snapshot of `hugovk/top-pypi-packages`.
- npm: a dated snapshot of `npm-high-impact` (chosen and verified in the
  context-and-reputation stage; see §9).

Both are committed with their date and URL.

**Residual gaps, stated rather than hidden.** These go into the README:
- ESL-002 does not judge the JavaScript file that an install script runs
  (`"postinstall": "node index.js"`), which is the most common shape of npm malware. The
  legitimate version of that exact shape (esbuild, sharp, puppeteer) downloads binaries with
  `child_process` and `https`, so a network-plus-exec rule on that file would not tell them
  apart. In that file, as in every file, only ESL-003 (a decoder adjacent to an evaluator)
  and ESL-004 (a credential source and a known exfiltration sink in the same file) apply;
  downloading and running code there is not flagged. The same holds for a shell script that
  an install script runs (`"postinstall": "sh setup.sh"`).
  For the same reason `node -e "require('./x')"` (core-js, es5-ext) is not flagged. Also
  not matched: `npx <pkg>` (`npx only-allow pnpm` is a common benign preinstall), inline
  code of other interpreters (`python -c`, `perl -e`, `bun -e`, `deno eval`), `sh -c`
  without a download tool or URL, shell quoting tricks that split a word (`c''url`,
  `n''ode`), and node reading code from stdin (`node < file`).
  The `node -e`/`-p` check emulates no shell: it fires when a node word is followed
  anywhere later in the same script by an eval flag word, ignoring separators and quoting.
  It may therefore over-fire when the `-e`/`-p` belongs to another command later in the
  same script (`node install.js && echo -e done`); each attempt to parse the shell
  instead (separators, quotes, CR, cmd.exe carets, bash `$'...'`) opened a way to hide
  a real `node -e`.
- `binding.gyp` command expansions (`<!(...)`), which node-gyp runs at install when a
  package has no install script, are not judged. The Miasma campaign (June 2026) used this
  to run a package's own `index.js` with no install script at all
  (<https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/>,
  checked 2026-10-12).
- ESL-001 reads only an sdist's `setup.py`. Code that runs when a wheel is imported
  (module-level `__init__.py`), the `import` lines of `.pth` files and Python 3.15 `.start`
  files (<https://peps.python.org/pep-0829/>, checked 2026-10-12) are read by ESL-003 and
  ESL-004 only, like any other file.
- ESL-004 misses exfiltration to an ordinary domain.
- ESL-003 misses multi-stage decoding split across lines.
- ESL-005 misses typosquats of packages outside the top 1,000.
- ESL-006 misses everything nobody has reported yet.

Engine: YARA for ESL-001, ESL-003 and ESL-004, applied to file bytes. ESL-002 parses
`package.json` with `json` and applies a YARA rule to the script strings for download
tools, pipes to a shell, `powershell -enc` and URLs; its `node -e`/`-p` check is a Python
token rule, not YARA. Typosquatting and OSV are plain Python.

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
 "eslabon":{"schema_version":"1.0","attack_version":"19.2","ecosystem":"pypi","scan_id":"…",
   "archive":{"sha256":"…"},
   "evidence":{"file":"setup.py","line":14,"snippet":"exec(<decoded payload>)","name_hex":"…"},
   "mitigation":{"action":"…","residual_gap":"…","detect":"…"}}}
```

- `ecs.version` holds the exact ECS release whose field reference `docs/event-schema.md` was
  written against. Recording it is part of the event stage's exit condition.
- `eslabon.archive.sha256` is the SHA-256 of the **downloaded or supplied archive**, not of
  the inner file that matched. That inner file is `eslabon.evidence.file`. The object is
  omitted when the hash is unknown.
- **No `file.*` (a documented deviation from ECS).** ECS would put the
  archive hash in `file.hash.sha256`, but Wazuh 4.14's `wazuh-alerts` template maps
  `data.file` as a keyword, so any object under `file` made the indexer reject the whole
  alert (lab pass 1: 14 alerts, 0 indexed). No event has a top-level `file` key and the
  schema rejects one. `schema_version` stayed `1.0`, since nothing had been published.
- `package.type` and `package.checksum` are **not** used. In ECS they mean the package file
  type and the hash of the installed package. The ecosystem goes in `eslabon.ecosystem` and
  the artifact hash in `eslabon.archive.sha256`.
- Every line is under **65,000 bytes** (`MAX_LINE_BYTES`). Wazuh 4.14's
  logcollector delivers at most 65,278 bytes plus the newline; in the lab a 65,300-byte line
  was dropped silently, and of the two small lines written after it the second was lost
  too. `write_events` raises
  rather than write a longer line. Every string value is also at most 32,766 UTF-8
  bytes, the indexer's keyword limit (lab experiment D); the caps below keep it far under
  that, and a test pins it.
- Every emitted path is capped at 512 characters and every hex field at 1,024 characters.
  A pax header can make a member name megabytes long.
- For a local archive, `package.name` and `package.version` are read from inside it (sdist
  `PKG-INFO`, wheel `METADATA`, npm `package.json`). They are attacker-controlled. If they
  are absent, the anomaly `no_metadata` is recorded and ESL-005 **and** ESL-006 fall back to
  the name (and version) in the archive's file name (`eslabon.identity_source: filename`),
  so breaking the metadata switches neither off; if both names exist and differ, both are
  checked and `identity_mismatch` is recorded (docs/event-schema.md). With no name from any
  source, the anomaly `no_identity` makes the scan `incomplete` (exit 2), and ESL-006 fails
  closed: `osv_status` is `unavailable`, not `skipped` (only `--offline` gives `skipped`).
- Arrays hold strings only. The Wazuh JSON decoder keeps string arrays but does not support
  arrays of objects.

**Scan summary** (`event.kind: event`, `event.dataset: eslabon.scan`): one per scan.
- `event.outcome`: `success` or `failure`.
- `eslabon.scan.status`: `ok`, `timeout`, `limits_exceeded`, `parse_error`,
  `hash_mismatch`, `fetch_error`, `incomplete` or `osv_unavailable`.
- `eslabon.scan.files_scanned`, `bytes_read`, `findings`, `anomalies` and `duration_ms`.

Without the summary, "zero findings" and "nothing arrived" look identical in the SIEM. With
it, the generate layer can be measured by counting.

**OSV unavailable** gives `status=osv_unavailable` and exit 2: "clean" must mean fully
checked. An archive with no package name to ask about is `osv_unavailable` too (fail
closed). `--offline` skips OSV explicitly and records `osv_status=skipped`; that is the
only way to get `skipped`. ESL-006 trusts the declared name and version: a renamed or
re-versioned known-bad artifact is left to the content rules (see docs/event-schema.md).

## 7. Integrations

**Wazuh** (`integrations/wazuh/`):
- `eslabon_v2_rules.xml`, installed on the manager as its own file,
  `/var/ossec/etc/rules/eslabon_v2_rules.xml`, so v1's rules are never edited. IDs
  **100300–100399**, group **`eslabon_v2`**, set once by the file's enclosing
  `<group name="eslabon_v2,">` and never repeated inside a rule: a per-rule copy made
  the alert's `rule.groups` list `eslabon_v2` twice in the lab run. The per-rule
  `<group>` adds only `supply_chain`, `sigma` or `scan_summary`. Wazuh produces **one alert per event**, so the
  rule tree is built so that each event reaches exactly one leaf rule. No custom decoder: the
  built-in `json` decoder handles lines that start with `{"`.
  - **Coexistence with eslabon v1.** The lab manager already runs the earlier eslabon, an
    orchestrator of external scanners, with rule IDs 100100–100170, group `eslabon`, and a
    base rule limited to `<location>eventos.jsonl$</location>`. This range, this group and
    this log path (`events.jsonl`) were chosen so the two never collide.
  - `100300` is the parent rule: `<decoded_as>json</decoded_as>` +
    `<location>events.jsonl$</location>` +
    `<field name="event.module" type="pcre2">^eslabon$</field>`, level 0 (every `<field>` is
    `type="pcre2"`, so Python's `re` in the tests is a faithful model). Limiting it to its own file is the practice v1 validated in the lab.
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
- Logtest samples: one line per rule plus scan summaries, generated on demand by
  `scripts/make_logtest_samples.py` (the real scanner over synthetic archives) and never
  committed; `integrations/wazuh/README.md` lists the rule each one must reach.
- A test asserts that the levels and `<mitre>` IDs in the XML match `catalog.toml`.

**Wazuh's ATT&CK database is v13.1** (since 4.8,
<https://wazuh.com/blog/introducing-wazuh-4-8-0/>, checked 2026-10-12), so the dashboard shows older names, e.g.
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
| Parser differentials | Paths are normalised the way npm and pip do (`\` → `/`, `./` and `//` collapsed, npm's first component stripped). **Duplicates:** there is no "last copy wins". Which copy an installer leaves on disk depends on the installer and the OS, so every copy is scanned, every copy's findings are reported, and the name gets a `duplicate_name` anomaly. **Uncertain landing place:** a name that normalisation rewrote (traversal, absolute, drive) or that contains a backslash or a NUL may land in different places for different installers. Such a member is still scanned but is never a metadata candidate; if any reading of its name would be one, the identity is `ambiguous_metadata` (no metadata name; ESL-005 falls back to the archive's file name). Zip names are judged on the stored `orig_filename`, not on `filename` (on Windows `zipfile` turns `\` into `/` there). A zip entry that looks like a directory but carries data is read and scanned as a file (`dir_with_content`); it is not excluded from metadata, so next to a real `METADATA` it makes the identity ambiguous. Case-only collisions, zip local/central name comparison beyond the exception above, and tar trailing-data detection are on the roadmap | Duplicate `package/package.json` is flagged and every copy is scanned and reported; a wheel whose `METADATA` is stored as `x.dist-info\METADATA` gives `ambiguous_metadata` |
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
- Every emitted line validates against the JSON Schema and is shorter than 65,000 bytes,
  and every emitted string is at most 32,766 UTF-8 bytes.
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
- The npm list's source was chosen in the context-and-reputation stage: `npm-high-impact`
  `lib/top-download.js` (wooorm/npm-high-impact, regenerated from ecosyste.ms data), ranked
  by downloads only, with more than 6,000 names. `scripts/update_top_lists.py` parses that JS array as
  text and never evaluates it. The PyPI list is `top-pypi-packages` (30-day downloads). Both bundled
  files record their source URL and retrieval date (UTC). The script refuses a list that
  lacks anchor names or that lost more than half of the previous top 1,000.
  ESL-005's name-only measurement is in docs/measurements.md (`scripts/measure_typosquat.py`).

**Lab measurement (end-to-end lab run):** three layers, counted separately.

| Layer | What is counted | Where |
|---|---|---|
| Generate | Lines in `events.jsonl`, per `rule.id` | Kali |
| Collect | Events received by the manager, whether or not a rule fires | `<logall_json>yes</logall_json>`, enabled only for the session, counted in `archives.json` |
| Detect | Alerts per `rule.id` in `wazuh-alerts-*` | The dashboard console-proxy query |

- **Expected:** N = N = N, and any difference is explained.
- **One deliberate experiment:** emit a 70 KB line and record what each layer does with it.
  The emitter cannot produce such a line, because of the line-length test, so the line is
  written by a separate script, `docs/evidence/lab/scripts/experiments.py` (the
  planned `scripts/oversize_line.py` was never created; this is the script that ran).
  Result (`docs/evidence/lab/`): 70,000- and 65,300-byte lines were dropped silently, and
  of the two small lines written after each, the second was lost too, which is why the
  line cap became 65,000 bytes. A 65,000-byte line was collected and alerted but not
  indexed, because its one long string exceeded the indexer's 32,766-byte keyword limit;
  real events stay far below both limits.

## 10. Stages

| Stage | Builds | Exit condition (shown by command output) |
|---|---|---|
| Base | Python 3.13 on the host (installed by the user), venv, `pyproject.toml`, ruff with `S` rules, pytest, `catalog.toml` | `pytest` and `ruff check` green. The first commit contains no ignored file |
| Hostile reading | `archive.py`, `worker.py` | All §8 tests green, including the hang test. `security-review` has no open finding |
| Event | Schema, `emit.py`, summary event, CLI on a local archive | `eslabon scan fixture.tgz` emits a summary that validates; the line-length test is green; `ecs.version` is recorded |
| Code heuristics | ESL-001…004 | 4 × (positive + near-miss) green, each seen red first |
| Context and reputation | ESL-005, ESL-006, `fetch.py` | Tests green; `eslabon scan requests==<pinned>` against the real registry ends with the hash verified |
| False positives | Corpus, `measure_fp.py`, ESL-005 name-only check | Table of fully scanned / incomplete / FP measured; every false positive either fixed in its rule or published; ESL-005 rate on ranks 5,001–6,000 measured. Target 0 |
| Offline integration | Wazuh XML, Sigma and its translation, logtest samples, agent snippet | Consistency tests green |
| Lab end to end | Kali snapshot, trimmed agent, Eslabon on Kali, logtest on the manager, three-layer count, 70 KB experiment | N = N = N (or explained), with the queries and their output saved as evidence; Kali restored |
| Publish | README with *"What this does not detect"*, `simplify`, `code-review`, `docs/roadmap.md`, writeup | Items 1–5 of §1 met, with their proof in the README, `docs/`, `tests/` and the commit history; item 6 (the writeup) written but kept outside this repository |

Every stage before *Lab end to end* needs no lab. That stage is the lab session and gets its writeup.

## 11. Things to verify, not assume

Each of these is checked in the stage named and recorded with its result:

| Check | Stage |
|---|---|
| The alert stores our fields as `data.rule.*`, separate from Wazuh's own `rule.*` | Lab end to end, `wazuh-logtest` |
| How a `<field>` matches against a string array (`threat.technique.id`) | Lab end to end |
| `$(rule.name)` and `$(package.name)` interpolate in rule descriptions | Lab end to end |
| `T1027.013` and `T1546.016` exist in Wazuh's v13.1 ATT&CK database | Lab end to end |
| What a 70 KB line and a UTF-8 BOM do at each layer | Lab end to end |
| Kali's `python3` version: 3.14 has no `yara-python` wheel | Lab end to end |

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
