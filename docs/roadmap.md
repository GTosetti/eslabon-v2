# Roadmap

Everything here is **out of v0.1**. Items 1-6 are `docs/design.md` §3, "Out", in its
order of priority. Item 7 holds the rule extensions: every per-rule gap that the
README's ["What this does not detect"](../README.md#what-this-does-not-detect) states,
with its origin. Nothing on this page is built.

## 1. Measuring detection against real samples

v0.1 measures false positives on 200 legitimate packages
([`measurements.md`](measurements.md)), and every rule has fired only on synthetic
fixtures. **How many real malicious packages it catches is not measured.** The source for
that is DataDog's malicious-packages dataset, and it is handled only inside Kali (design
§8: suspicious packages are analysed only in Kali; the host runs the test suite and the
legitimate corpus only).

Procedure:

1. **Snapshot Kali, cold.** Shut the VM down first: on the lab host a live snapshot never
   converged under Hyper-V ([`evidence/e7/README.md`](evidence/e7/README.md),
   "Incidents").
2. **Clone the dataset inside Kali**, never on the host.
3. **Decrypt inside Kali**, into a directory that is not shared with the host, and run
   `eslabon scan` over each archive there with **`--offline`**, so the rate measures
   ESL-001..005. Nothing is installed or executed: Eslabon reads the archives in memory.
4. **Report ESL-006 separately**, in a second run without `--offline`. Known samples are
   by definition already reported, so OSV `MAL-` hits would count reports, not
   detection, and would inflate a combined rate.
5. **Export only results**: the JSON Lines events and the per-rule counts. No sample,
   archive or decrypted file leaves the VM.
6. **Restore** Kali to the snapshot, and confirm the restore as in E7
   (`currentStateModified="false"` in the `.vbox` file).

What to publish: the detection rate per rule and per ecosystem (ESL-001..005 offline,
ESL-006 apart), next to the false-positive table, with the same "measured, not proven"
caveat.

## 2. `.pth` files that `import` at interpreter startup

From design §3. A `.pth` file is scanned like any other member (ESL-003 and ESL-004 run
on every file), but no rule judges a `.pth` line that imports code at interpreter
startup.

## 3. Archive anomalies beyond v0.1

From design §3 and §8:
- case-only name collisions;
- comparing a zip entry's local-header name with its central-directory name, beyond the
  `BadZipFile` case v0.1 already records;
- tar trailing data.

Routed here by the Task 4 review (tar reading):
- data hidden in tar member padding, or skipped through a pax `size` override;
- GNU sparse extension blocks (a sparse member is recorded and the scan is
  `incomplete`, but its content is not reconstructed);
- the tar reader relies on `tarfile` internals, which are only partly guarded by tests.

Routed here by the false-positive measurement ([`measurements.md`](measurements.md),
ruling R50):
- when a PyPI sdist hits a cap, fall back to the wheel;
- skip an oversize member, record an anomaly and continue, instead of aborting the rest
  of the archive. Today a cap stops the scan and the summary is `limits_exceeded`, which
  must be triaged as an unscanned remainder, never as clean.

## 4. Dependency files

`requirements.txt` and `package-lock.json` are not read. Eslabon scans one package
archive at a time.

## 5. Entropy, metadata signals, steganography, bundled binaries

From design §3: entropy; metadata signals such as package age, a missing repository or
odd version jumps; steganography; bundled binaries.

## 6. Syslog/CEF output; publishing to PyPI

Output today is JSON Lines only. The name `eslabon` was free on PyPI and npm on
2026-10-05 (design §3); v0.1 is not published to either.

## 7. Rule extensions

The residual gaps of each v0.1 rule, in the order the README states them. Origins:
design §5 (residual gaps), the catalog's `residual_gap` text, and the reviews of v0.1.

**ESL-001** (`pypi-install-exec`)
1. **In-tree PEP 517 build backends** (ruling R59, found in the Task 19b review). An
   sdist with no `setup.py` whose `pyproject.toml` sets `backend-path = ["."]` and a
   `build-backend` shipped in the archive has that module run by pip at build time, like
   `setup.py`. A network call in it gives 0 findings and exit 0 today. The extension:
   judge the backend module named by `pyproject.toml` the way `setup.py` is judged.
2. A `setup.py` that fetches or runs code through a helper module (catalog
   `residual_gap`).
3. A download command assembled indirectly, for example through string formatting or a
   `shutil.which` lookup, rather than written next to the `subprocess`/`os.system` call
   (Task 10 review).

**ESL-002** (`npm-install-script-exec`), all from design §5:
1. The JavaScript file an install script runs (`"postinstall": "node index.js"`), the most
   common shape of npm malware. The legitimate shape (esbuild, sharp, puppeteer) also
   downloads binaries, so a network-plus-exec rule on that file would not tell them
   apart; ESL-003 and ESL-004 cover it meanwhile.
2. `node -e "require('./x')"` (the core-js and es5-ext shape).
3. `npx <pkg>`.
4. Inline code of other interpreters: `python -c`, `perl -e`, `bun -e`, `deno eval`.
5. `sh -c` without a download tool or URL.
6. Shell quoting that splits a word.
7. node reading code from stdin.
8. Over-firing: the `node -e`/`-p` check emulates no shell, so it may fire when the
   `-e`/`-p` belongs to a later command in the same script. Every attempt to parse the
   shell instead opened a way to hide a real `node -e` (design §5).

**ESL-003** (`encoded-exec`)
1. Multi-stage decoding split across lines, so decoder and evaluator are not adjacent
   (design §5).
2. A gap of more than 50 characters between evaluator and decoder (Task 9 review).
3. JavaScript evaluators other than a direct `eval` or `Function` call: the `vm` module's
   run functions, a timer given a decoded string, an indirect or bracket-notation `eval`
   (Task 9 review).
4. Python evaluators reached through aliases, `getattr` or the `builtins` module (Task 9
   review).

**ESL-004** (`secret-exfil`)
1. Exfiltration to an ordinary domain: only known sinks and public IP literals count
   (design §5).
2. Environment exfiltration that iterates over the variables instead of serialising the
   whole environment (ruling R40).

**ESL-005** (`typosquat`)
1. Typosquats of packages ranked below 1,000 (design §5). On npm this misses historical
   squats of `jquery`, `cross-env` and `mongoose` ([`measurements.md`](measurements.md)).
   Raising the npm cutoff to 2,000 was measured at +6 false positives per 1,000 names for
   +2 historical hits, and was not taken (ruling R44).
2. A weak signal alone: pair it with ESL-001..004 (catalog `residual_gap`).

**ESL-006** (`known-malicious`)
1. Releases nobody has reported yet are invisible (design §5).
2. It trusts the declared name and version: a renamed or re-versioned known-bad artifact
   is left to the content rules (design §6).

**Wazuh's ATT&CK view**
- Wazuh's bundled ATT&CK database is older than the v19.2 the events carry: the alert
  shows *Defense Evasion* where the event says *Stealth*, and T1027.013 is missing, so
  rule 100303 uses T1027 ([`evidence/e7/README.md`](evidence/e7/README.md),
  [`integrations/wazuh/README.md`](../integrations/wazuh/README.md)). To do: re-check
  every `<mitre>` ID with `wazuh-logtest` whenever Wazuh updates its database, and drop
  the override when T1027.013 appears.
