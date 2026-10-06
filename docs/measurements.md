# Measurements

## ESL-005 typosquat (name only)

Rule as ruled in R43 (variant "D+G"; see the ESL-005 row in design.md section 5).
Measured on 2026-10-06 with `scripts/measure_typosquat.py`, which calls the real
`eslabon.typosquat.check` on the bundled lists:

- PyPI list: `top-pypi-packages` (hugovk), retrieved 2026-10-06 (UTC).
- npm list: `npm-high-impact` `lib/top-download.js` (wooorm, downloads-only ranking),
  retrieved 2026-10-06 (UTC). Its first 6,000 names are identical to `lib/top.js`, used
  before: the switch changed the source, not the list.

False positives = flagged names among ranks 5,001-6,000 of each list (popular legitimate
packages just outside the exemption). Recall = flagged names among known-malicious
typosquat names from OSV `MAL-` advisories (`positives`: distance-1 and affix shapes;
`positives_d2`: distance-2 shapes), plus a small built-in set of historical squats.

| ecosystem | FP ranks 5001-6000 | recall positives | recall positives_d2 | recall historical |
|---|---|---|---|---|
| pypi | 14/1000 (1.4%) | 442/455 | 14/15 | 6/6 |
| npm | 11/1000 (1.1%) | 90/121 | 9/11 | 1/8 |

For comparison, the first implementation (task 13, threshold 1/2, scopes stripped on both
sides) gave 33/1000 (PyPI) and 92/1000 (npm) false positives on the same lists.

The reviewer's independent harness (variant G) gives the same numbers.

### Known false positives

These are listed here by name instead of being suppressed. There is no allowlist.

- PyPI: `gitdb2 ~ gitdb`, `elasticsearch8 ~ elasticsearch`, `pottery ~ poetry`,
  `langchain-cohere ~ langchain-core`, `murmurhash2 ~ murmurhash`,
  `progressbar ~ progressbar2`, `willow ~ pillow`, `ratelimiter ~ ratelimit`,
  `ptable ~ pathable`, `nvidia-ml-py3 ~ nvidia-ml-py`, `pytest-cover ~ pytest-cov`,
  `djangoql ~ django`, `smmap2 ~ smmap`, `acachecontrol ~ cachecontrol`.
- npm: `dom-serialize ~ dom-serializer`, `echarts ~ recharts`,
  `@ljharb/through ~ through` (scope confusion), `@exodus/bytes ~ bytes` (scope
  confusion), `nprogress ~ progress`, `flatten ~ flatted`, `yazl ~ yaml`,
  `flattie ~ flatted`, `rehackt ~ react`, `execall ~ execa`,
  `@develar/schema-utils ~ schema-utils` (scope confusion).

### Known gaps

- Only the top 1,000 are targets. Squats of packages ranked lower are missed. Historical
  npm squats such as `jquerry`, `crossenv`, `mongose`, `electorn` and `discordi.js` target
  `jquery` (rank 1,888), `cross-env` (1,931) and `mongoose` (4,415). `electron` and
  `discord.js` are not in the top 6,000 at all. A downloads ranking is dominated by
  transitive dependencies.
- Trailing-digit names are reported on purpose (`urllib33`, `beautifulsoup44` are real
  malicious packages). That causes most of the PyPI false positives above.

The same counts were obtained again on 2026-10-06 when the false-positive measurement
below was run (task 16).

## False positives on the legitimate corpus (ESL-001..006)

### Corpus

`corpus/legit.toml` pins the first 100 names of each bundled top list (the same lists as
above) to their latest registry version: PyPI `info.version` from
`https://pypi.org/pypi/<name>/json`, npm `https://registry.npmjs.org/<name>/latest`
(the registry's `dist-tags.latest`). It was generated on **2026-10-06T14:07:28Z (UTC)** by
`scripts/build_corpus.py`, which reads registry JSON metadata only (through
`eslabon.fetch`) and checks with `fetch.resolve` that the exact version has an artifact
`eslabon scan` would download. No name was skipped. SHA-256 of the file as committed (LF
line endings): `8c911be00db6af646ffa722fe173041ae77c227ca427fbce6037b3efc605a26c`.

### Method

`scripts/measure_fp.py` runs `python -m eslabon scan name==version --ecosystem E --out
<tmp>/NNN.jsonl` once per package, sequentially, with a 300 s wall timeout, on the host
(these are legitimate packages; nothing is installed or executed). OSV is queried
(no `--offline`), so ESL-006 is measured too. Any finding on a corpus package is a false
positive. The JSONL and `results.json` stay in a temporary directory outside the
repository. Run on 2026-10-06.

### Result

| ecosystem | packages | fully scanned | incomplete | packages with >=1 false positive |
|---|---|---|---|---|
| pypi | 100 | 95 | 5 | 0 |
| npm | 100 | 99 | 1 | 0 |
| total | 200 | 194 | 6 | 0 |

Claim for the README: **0 false positives on 194 of 200 fully scanned** packages, with
the 6 incomplete scans below. No rule (ESL-001..006) fired on any package, incomplete
ones included. OSV answered for all 200 (`osv_status=ok`); no `MAL-` record matched a
latest version. Exit codes: 194 x 0, 6 x 2 (the incomplete ones). No rule was changed.

Timing: 568 s of wall time for the 200 subprocesses (median 2.6 s, max 11.8 s per
package, download and OSV included); the scan itself (`duration_ms`) had a median of
about 0.34 s and a maximum of 4.0 s. 50,020 members and 884 MB of decompressed data were
read. Anomalies: `link_skipped` in 3 packages (referencing, pyparsing,
beautifulsoup4: symlinks in the sdist, skipped by design).

### Incomplete scans

All six are `limits_exceeded` from Eslabon's own caps (`Limits`: 5,000 members, 10 MiB
per member). They give no verdict. They are the caps working as designed, not parser
bugs, so they are listed instead of raised. For PyPI the sdist is chosen first
(`setup.py` lives there), and sdists of compiled projects carry vendored sources.

| package | status | cause (member listing of the same artifact) |
|---|---|---|
| pypi numpy==2.5.3 | limits_exceeded | 8,367 members; 5,320 under `vendored-meson/` |
| pypi grpcio==1.84.0 | limits_exceeded | 6,274 members (5,449 files); 2,778 under `third_party/` |
| pypi ruff==0.16.10 | limits_exceeded | 5,083 members, almost all under `crates/` |
| pypi scipy==1.18.1 | limits_exceeded | 5,076 members; 1,885 under `subprojects/` |
| pypi lxml==6.1.3 | limits_exceeded | `src/lxml/etree.c` is 12,822,971 bytes (generated Cython C) |
| npm @esbuild/linux-x64==0.28.2 | limits_exceeded | `package/bin/esbuild` is 11,427,952 bytes (the Go binary); 3 members in total |

A diagnostic pass outside the shipped pipeline (every member up to 10 MiB, no member
cap) found no ESL-001, ESL-003 or ESL-004 condition met in these six either.

### Watch list from the reviews

Checked explicitly, with the rule strings matched one by one (conditions relaxed to
"any string") over every member of the 200 corpus archives, plus extra scans of legitimate
packages outside the top 100.

- **ESL-001** (only the top-level `setup.py` pip runs): 36 of the 100 PyPI artifacts have
  one. Not a single ESL-001 string matched in any of them, so the echo+URL via
  `os.system`/`subprocess`, an inline `long_description` quoting a requests GET call and
  a comment naming urllib's urlopen shapes did not occur in this corpus. They stay
  unmeasured, not disproved.
- **ESL-002** (R38 cost of the node -e/-p token rule): only 3 of the npm top 1,000 have a
  `preinstall`/`install`/`postinstall` script (from `/<name>/latest` metadata): esbuild
  and pnpm (`node install.js`) and core-js (`node -e "try{require('./postinstall')}..."`,
  the local-require exemption). None fires. No `node x.js && mkdir -p`, `cp -p`,
  `sed -e`, `grep -e`, `echo -e` or `npm -p` after a node word occurs, so R38's accepted
  over-firing costs 0 packages here.
- **ESL-003**: no ESL-003 string matched anywhere in the corpus, nor in the security-tool
  packages scanned additionally (bandit 1.9.4, semgrep 1.179.0, pip-audit 2.10.1,
  safety 3.8.1, detect-secrets 1.5.0, npm eslint-plugin-security 4.2.0): all clean.
- **ESL-004**: the compound "same file" condition is what keeps the corpus clean.
  Credential sources alone appear in 15 corpus packages (boto3, botocore, aiobotocore,
  s3fs, pyarrow: the AWS shared credentials file path in docs, examples and
  `configprovider.py`; cryptography, pyasn1, numpy CI config: the SSH RSA key path;
  setuptools, pip's vendored distlib, iniconfig, ruff's typeshed, `.gitignore` files: the
  PyPI rc file). Sinks alone appear in 31 (mostly IP-literal URLs; plus the Slack
  incoming-hooks host in a yarl test and the Telegram bot API host in
  `tqdm/contrib/telegram.py`). No file has both. The quoted path-segment forms of the
  SSH key and AWS credentials paths did not occur.
  Scanned additionally: paramiko 5.0.0 and fabric 3.2.3 (fully scanned, clean; the SSH
  key path only in tests/docs), awscli 1.46.1 (incomplete: more than 5,000
  members) and npm aws-sdk 2.1693.0 (incomplete: a member over 10 MiB). In awscli and aws-sdk
  credential paths (AWS credentials, npm rc, kube config) and sinks (the IMDS link-local
  address, documentation IPs) occur, but never in the same file.

### Known false positives

None on this corpus.
