# Roadmap

Everything here is **out of v0.1**. Items 1-6 are `docs/design.md` §3, "Out", in its
order of priority. Item 7 holds the rule extensions: every per-rule gap that the
README's ["What this does not detect"](../README.md#what-this-does-not-detect) states,
with its origin. Items 8 and 9 came from an adversarial review of v0.1. Nothing on this
page is built.

## 1. Measuring detection against real samples

v0.1 measures false positives on 200 legitimate packages
([`measurements.md`](measurements.md)), and every rule has fired only on synthetic
fixtures. **How many real malicious packages it catches is not measured.** The source for
that is DataDog's malicious-packages dataset, and it is handled only inside Kali (design
§8: suspicious packages are analysed only in Kali; the host runs the test suite and the
legitimate corpus only).

Procedure:

0. **Check the sample format, then repack.** Inside Kali, open 3-5 samples per ecosystem
   and record what they contain. The dataset's README shows that unzipping a sample
   creates a directory
   ([DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset),
   checked 2026-10-12), which points to an extracted tree rather than the original
   tarball, but does not prove it. Eslabon reads archives only, so the base plan is a
   deterministic repack inside Kali (`tar` with a `package/` prefix for npm,
   `<name>-<version>/` for PyPI), with the repack rule published next to the results. If
   the samples turn out to be the original tarballs, they are scanned as they are.
   **Classify every PyPI sample** as an sdist (`PKG-INFO` and `setup.py` at the top) or a
   wheel (a `*.dist-info` directory) before measuring, and report the split: ESL-001
   judges only the `setup.py` of an sdist, so a wheel can never be an ESL-001 hit.
1. **Snapshot Kali, cold.** Shut the VM down first: on the lab host a live snapshot never
   converged under Hyper-V ([`evidence/lab/README.md`](evidence/lab/README.md),
   "Incidents").
2. **Clone the dataset inside Kali**, never on the host.
3. **Decrypt inside Kali**, into a directory that is not shared with the host, and run
   `eslabon scan` over each archive there with **`--offline`**, so the rate measures
   ESL-001..005. Nothing is installed or executed: Eslabon reads the archives in memory.
4. **Report ESL-006 separately**, in a second run without `--offline`. Known samples are
   by definition already reported, so OSV `MAL-` hits would count reports, not
   detection, and would inflate a combined rate.
5. **Export only counts**: per sample its ecosystem, category, year, scan status and the
   rule IDs that fired, plus the per-rule totals. **The JSON Lines events stay in the
   VM**: each finding carries `evidence.snippet`, up to 1,024 characters of the matched
   code, so exporting the events would carry fragments of malicious code to the host. No
   sample, archive, decrypted file, event or snippet leaves the VM.
6. **Restore** Kali to the snapshot, and confirm the restore as in the lab run
   (`currentStateModified="false"` in the `.vbox` file).

**No sample content is ever passed to an LLM.** No snippet, file or output from a real
sample is pasted into an AI assistant, whether to triage it or to review code: sample
content is hostile input and may carry text written to steer an automated analyser. Only
the counts above leave the VM.

How a sample counts: a **hit** is a scan with status `ok` and at least one ESL-001..004
finding; a **miss** is `ok` with none; any other status is **no verdict** and is
published apart, never folded into hits or misses. ESL-005 is reported apart too, so
that easy typosquats do not inflate the content rules' rate.

What to publish: the detection rate per rule and per ecosystem (ESL-001..005 offline,
ESL-006 apart), next to the false-positive table, with the same "measured, not proven"
caveat. **Bias to state with it:** the dataset's samples were mostly flagged by GuardDog
([dataset README](https://github.com/DataDog/malicious-software-packages-dataset),
checked 2026-10-12), so the rate is recall on what one tool already detects. Running
GuardDog over the same samples inside Kali and publishing both rates side by side
measures that bias instead of only stating it.

## 2. Code that runs on import or at interpreter startup

From design §3. A `.pth` file is scanned like any other member (ESL-003 and ESL-004 run
on every file), but no rule judges a `.pth` line that imports code at interpreter
startup. A `.pth` line that decodes and evaluates on the same line is caught by ESL-003;
one that only imports and fetches is not.

Python 3.15 adds `.start` files as the new interpreter-startup hook and deprecates `import`
lines in `.pth` files ([PEP 829](https://peps.python.org/pep-0829/), checked 2026-10-12).
`.start` files are not judged either. The extension should judge the content of both
kinds of file without depending on the target's Python version.

Code that runs when a wheel is imported (module-level code in `__init__.py`) is not judged
either: ESL-001 reads only the top-level `setup.py` of an sdist, so a wheel that downloads
on import gives 0 findings and exit 0. ESL-003 and ESL-004 still run on those files. The
in-tree PEP 517 build backend, the other Python code pip runs, is §7, ESL-001 item 1.

## 3. Archive anomalies beyond v0.1

From design §3 and §8:
- case-only name collisions;
- comparing a zip entry's local-header name with its central-directory name, beyond the
  `BadZipFile` case v0.1 already records;
- tar trailing data.

Routed here by the review of the tar reader:
- data hidden in tar member padding, or skipped through a pax `size` override;
- GNU sparse extension blocks (a sparse member is recorded and the scan is
  `incomplete`, but its content is not reconstructed);
- the tar reader relies on `tarfile` internals, which are only partly guarded by tests.

Routed here by the false-positive measurement ([`measurements.md`](measurements.md)):
- skip an oversize member, record an anomaly and continue, instead of aborting the rest
  of the archive. Today a cap stops the scan and the summary is `limits_exceeded`, which
  must be triaged as an unscanned remainder, never as clean. The skipped member still
  makes the scan `incomplete`, so this alone does not turn an exit 2 into a verdict; it
  lets the rest of the archive be read and its findings emitted.
- read the members that decide what runs first (`setup.py`, `pyproject.toml`,
  `package.json`, `binding.gyp`, `*.pth`, `__init__.py`), so that a package padded with
  thousands of members, or with a huge first member, still has those read before a cap
  stops the scan.

Falling back to the wheel when a PyPI sdist hits a cap was listed here, on the premise
that the wheel fits within the caps. **For most of these packages it does not.** Four of
the five PyPI packages that stopped at a cap ship manylinux x86_64 wheels that carry a
member over the 10 MiB per-file cap: numpy 2.5.3 (`_multiarray_umath…so`, 10,633,113
bytes, and `libscipy_openblas64_…so`, 24,325,657), scipy 1.18.1 (`libscipy_openblas…so`,
25,094,609), ruff 0.16.10 (`ruff-0.16.10.data/scripts/ruff`, 23,998,752) and grpcio
1.84.0 (`cygrpc…so`, 16,619,808). Measured on 2026-10-12 by reading only each wheel's
zip central directory over HTTP range requests, with nothing decompressed. The per-file
cap aborts the rest of the archive just as the member-count cap does in their sdists, so
scanning the wheel alone would clear only lxml's exit 2. Skipping the oversize member
comes first; which artifact to scan is §8.

## 4. Dependency files

`requirements.txt` and `package-lock.json` are not read. Eslabon scans one package
archive at a time.

A different gap from the project's own dependency files: the dependencies a package
declares **inside its own `package.json`** by URL or git (`http://`, `git+`, `github:`)
are not judged either. The registry shows such a package with no dependencies, and what
the URL serves is never fetched or scanned. GuardDog 3 already has a rule for this signal
(`direct_url_dependency.py` in
[`guarddog/analyzer/metadata/npm`](https://github.com/DataDog/guarddog/tree/v3/guarddog/analyzer/metadata/npm),
checked 2026-10-12); what Eslabon would add is the alert: technique, mitigation, residual
gap and a validated Wazuh rule.

For npm, only the `package.json` inside the tarball is read. If the manifest the registry
serves declares different dependencies or scripts (manifest confusion), that difference
is not checked.

## 5. Entropy, metadata signals, steganography, bundled binaries

From design §3: entropy; metadata signals such as package age, a missing repository or
odd version jumps; steganography; bundled binaries.

Not built either: hallucinated package names, VS Code and Open VSX extensions, pickled ML
models. A `prepare` script in a published tarball is not judged. A new-version signal
such as package age would only be a weak signal, paired with ESL-001..004 like ESL-005,
because popular packages publish new versions all the time.

## 6. Syslog/CEF output; publishing to PyPI

Output today is JSON Lines only. The name `eslabon` was free on PyPI and npm on
2026-10-05 (design §3); v0.1 is not published to either.

## 7. Rule extensions

The residual gaps of each v0.1 rule, in the order the README states them. Origins:
design §5 (residual gaps), the catalog's `residual_gap` text, and the reviews of v0.1.

**ESL-001** (`pypi-install-exec`)
1. **In-tree PEP 517 build backends** (found in a v0.1 review). An
   sdist with no `setup.py` whose `pyproject.toml` sets `backend-path = ["."]` and a
   `build-backend` shipped in the archive has that module run by pip at build time, like
   `setup.py`. A network call in it gives 0 findings and exit 0 today. The extension:
   judge the backend module named by `pyproject.toml` the way `setup.py` is judged.
2. A `setup.py` that fetches or runs code through a helper module (catalog
   `residual_gap`).
3. A download command assembled indirectly, for example through string formatting or a
   `shutil.which` lookup, rather than written next to the `subprocess`/`os.system` call
   (v0.1 review).

**ESL-002** (`npm-install-script-exec`), items 1-8 from design §5:
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
9. `binding.gyp` command expansions (`<!(...)`). When a package has a `binding.gyp` and no
   install script, npm runs node-gyp at install, and node-gyp runs those expansions; with
   no install script, ESL-002 has nothing to judge. The Miasma campaign used a target
   with `"sources": ["<!(node index.js > /dev/null 2>&1 && echo stub.c)"]` to run the
   package's own `index.js` with no install script at all
   ([Snyk](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/),
   checked 2026-10-12). An extension must cover an expansion that downloads and one
   that runs a file shipped in the package (adversarial review).
10. A shell script that an install script runs (`"postinstall": "sh setup.sh"`). It is
    read like any other file, so only ESL-003 (decoding next to an evaluator) and ESL-004
    (credential path next to a known sink) apply to it; download-and-execute in it is not
    judged (adversarial review).

**ESL-003** (`encoded-exec`)
1. Multi-stage decoding split across lines, so decoder and evaluator are not adjacent
   (design §5).
2. A gap of more than 50 characters between evaluator and decoder (v0.1 review).
3. JavaScript evaluators other than a direct `eval` or `Function` call: the `vm` module's
   run functions, a timer given a decoded string, an indirect or bracket-notation `eval`
   (v0.1 review).
4. Python evaluators reached through aliases, `getattr` or the `builtins` module (v0.1
   review).

**ESL-004** (`secret-exfil`)
1. Exfiltration to an ordinary domain: only known sinks and public IP literals count
   (design §5).
2. Environment exfiltration that iterates over the variables instead of serialising the
   whole environment.

**ESL-005** (`typosquat`)
1. Typosquats of packages outside the top 1,000 (design §5). On npm this misses historical
   squats of `jquery`, `cross-env` and `mongoose` ([`measurements.md`](measurements.md)).
   Raising the npm cutoff to 2,000 was measured at +6 false positives per 1,000 names for
   +2 historical hits, and was not taken.
2. A weak signal alone: pair it with ESL-001..004 (catalog `residual_gap`).

**ESL-006** (`known-malicious`)
1. Releases nobody has reported yet are invisible (design §5).
2. It trusts the declared name and version: a renamed or re-versioned known-bad artifact
   is left to the content rules (design §6).

**Wazuh's ATT&CK view**
- Wazuh's bundled ATT&CK database is older than the v19.2 the events carry: the alert
  shows *Defense Evasion* where the event says *Stealth*, and T1027.013 is missing, so
  rule 100303 uses T1027 ([`evidence/lab/README.md`](evidence/lab/README.md),
  [`integrations/wazuh/README.md`](../integrations/wazuh/README.md)). To do: re-check
  every `<mitre>` ID with `wazuh-logtest` whenever Wazuh updates its database, and drop
  the override when T1027.013 appears.

## 8. Scanning the artifact pip installs

In registry mode Eslabon scans one artifact per PyPI version: the sdist when there is one
(`setup.py`, which ESL-001 judges, lives there). pip installs a compatible wheel before
falling back to an sdist (`CandidateEvaluator._sort_key` in
[pip's `package_finder.py`](https://github.com/pypa/pip/blob/main/src/pip/_internal/index/package_finder.py),
checked 2026-10-12), so a clean sdist next to a malicious wheel scans clean. The same
holds for the 0 false positives of [`measurements.md`](measurements.md): for PyPI they
were measured on sdists. GuardDog also scans one archive per PyPI version, its source
tarball ([GuardDog `v3` README](https://github.com/DataDog/guarddog/tree/v3), checked
2026-10-12): the gap is not Eslabon's alone.

Until this is built, scan the wheel you will install as a local file:

```
pip download <name>==<version> --no-deps --only-binary :all: \
    --platform manylinux_2_28_x86_64 --python-version 3.13 --abi cp313 -d <dir>
eslabon scan <dir>/<file>.whl
```

`--only-binary :all:` is required: without it pip may fall back to the sdist and build
it, which runs its `setup.py` on the analyst's machine (design §8). `--platform`,
`--python-version` and `--abi` are required too: without them pip picks the wheel for the
analyst's own machine, not for the server where the package will be installed. Set them
to the target.

Planned, in this order:
1. Record which file was scanned (`filename`, `packagetype`) in the event, so the analyst
   sees it in Wazuh. This changes the schema and repeats the three-layer lab validation.
2. An explicit option to choose the artifact (a file name, `sdist` or `wheel`).
3. Scan every artifact of the release, with per-release caps and findings deduplicated
   by member content, as one scan summary per release. **Only after** §3's "skip an
   oversize member": native wheels carry members over 10 MiB, so without it this would
   add `limits_exceeded` results instead of removing them. A cheaper variant lists each
   wheel's members from its zip central directory over HTTP range requests and downloads
   and scans in full only a wheel that differs from the sdist (a `.pth` or `.start`
   file, members the sdist lacks, a different `__init__.py`). A partial read cannot be
   checked against the file's SHA-256, so the listing is for triage only and anything
   scanned is downloaded whole.

## 9. Release-to-release delta

Eslabon judges one archive; it does not compare a release with the previous one (a new
install script, a new URL dependency, a new `.pth` file, a new native binary). That is
the signal against an account takeover, where a legitimate package publishes a
malicious version. GuardDog 3 already has rules for a new install script and a risky new
dependency (`new_install_script.py`, `risky_new_dependency.py` in
[`guarddog/analyzer/metadata/npm`](https://github.com/DataDog/guarddog/tree/v3/guarddog/analyzer/metadata/npm),
checked 2026-10-12), and [malcontent](https://github.com/chainguard-dev/malcontent)
(checked 2026-10-12) has a `diff` mode between two versions; use them for this today. If
built here, it depends on §8: which artifact represents a version has to be settled first.
