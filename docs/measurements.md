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
