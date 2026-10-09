# Eslabon v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A static detector for malicious PyPI and npm packages. It never installs or
executes them, emits ECS-style JSON Lines events, and is validated end to end on the lab's
Wazuh 4.14.7.

**Architecture:**
- A CLI fetches or opens an archive and reads it in memory, streaming and capped, inside a
  child process with a wall-clock timeout.
- It runs six heuristics: YARA for code, plus Python for typosquatting and OSV.
- It writes one finding event per (rule, file), plus one summary event per scan.
- `catalog.toml` is the single source of truth for every rule.

**Tech Stack:** Python 3.13, `yara-python` 4.5.4 (the only runtime dependency), pytest,
ruff (including the `S` rules), jsonschema (dev only), Wazuh 4.14 rules XML, Sigma.

**Spec:** `docs/design.md`. Section numbers below (§N) refer to it.

## Global Constraints

- Python `>=3.13`. Runtime dependencies: `yara-python==4.5.4` only. Dev: `pytest`, `ruff`,
  `jsonschema`.
- Package code is never imported, executed, installed or extracted to disk. Never run
  `pip install <name>`, `pip download`, `npm install/pack`, `setup.py` or `node` on analysed
  content.
- Fixtures that look malicious are **built at test runtime**: suspicious tokens are
  concatenated in the test source, e.g. `"ex" + "ec("`. Domains are `example.invalid`.
  Decoded payloads are `print('eslabon-fixture')`. No archive is ever committed.
- Limits (§8): download 50 MiB, total decompressed 200 MiB, per file 10 MiB, 5,000 members,
  zip central directory ≤ 5,000 × (46 + 512) bytes, worker timeout 120 s, YARA timeout 10 s
  per file. All limits live in one `Limits` dataclass.
- Exit codes: `0` clean, `1` findings, `2` error or incomplete scan. `2` wins over `1`.
- Output: UTF-8 without BOM, one JSON object per line, every line < 65,000 bytes (ruling
  R54: Wazuh 4.14's logcollector delivers at most 65,278 bytes; was 65,536), every string
  value ≤ 32,766 UTF-8 bytes (indexer keyword limit, E7 experiment D), snippet
  ≤ 1,024 characters, every emitted path ≤ 512 characters, every hex field ≤ 1,024
  characters, arrays contain strings only.
- Local archives larger than `max_download` are refused with `stat()` before they are
  opened, so the same cap applies to local and downloaded input.
- Status precedence when several apply: `timeout` > `limits_exceeded` > `parse_error` >
  `hash_mismatch` > `fetch_error` > `incomplete` > `osv_unavailable` > `ok` (`incomplete`
  added by ruling R22).
- Wazuh rule IDs `100300`–`100399`, group `eslabon_v2`, log path ending in `events.jsonl`.
  Never touch IDs `100100`–`100199`, which belong to eslabon v1.
- ATT&CK version `19.2`. No Wazuh level 15 anywhere.
- Code, comments, docs and commits are in English. Commits end with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Licence: Apache-2.0, the same as eslabon v1.
- Progress is stated in stages E0–E8 with exit conditions, never in time.

## Review Focus

1. **One Wazuh alert per event.** Two rules that both match one event do not add up; only
   one alert is produced. The rule tree must give every event exactly one intended alert.
   Pinned in Task 17 (`test_rule_tree_one_alert_per_event`) and checked with logtest in
   Task 18.
2. **A worker that dies without answering** (segfault in a native parser, `os._exit`):
   reported promptly as `parse_error` with its exit code, never as a 120 s `timeout` and
   never as `ok`. Pinned in Task 6.
3. **Unbounded attacker-controlled names** (a 1 MB pax `path`): every emitted path is capped
   at 512 characters and every hex field at 1,024, so the line stays under 65,000 bytes
   and every string under 32,766 bytes. Pinned in
   Task 7.
4. **Binary members** (`.so`, `.png`, `.node`) inside an archive: scanned without crashing,
   and a snippet near a match decodes with `errors="replace"`. Pinned in Task 9.
5. **Malformed targets and names** (`requests=2`, `requests==`, `./missing.tgz`, an unknown
   extension without `--ecosystem`, `Django`, `typing_extensions`, `@types/node`): either
   exit 2 with a one-line message on stderr and no traceback, or resolve correctly. Pinned in
   Tasks 8, 13 and 15.

---

## File structure

```
pyproject.toml  .gitattributes  LICENSE  README.md
src/eslabon/__init__.py        __version__ = "0.1.0"
src/eslabon/__main__.py        python -m eslabon -> cli.main()
src/eslabon/model.py           Limits, Member, Anomaly, Finding, PackageRef, ScanResult, exceptions
src/eslabon/catalog.toml       the 6 rules (§5)
src/eslabon/catalog.py         Rule, load_catalog()
src/eslabon/sanitize.py        clean_text(), to_hex()
src/eslabon/archive.py         iter_members()
src/eslabon/worker.py          run_isolated()
src/eslabon/yara_engine.py     compile_rules(), scan_member()
src/eslabon/rules/esl001.yar esl002.yar esl003.yar esl004.yar
src/eslabon/npm_scripts.py     scan_package_json()
src/eslabon/typosquat.py       normalize(), distance(), check()
src/eslabon/data/top_pypi.json top_npm.json   {"source","retrieved","names":[...]}
src/eslabon/osv.py             query_malicious()
src/eslabon/fetch.py           resolve(), download()
src/eslabon/scan.py            analyze_archive()  (runs inside the worker)
src/eslabon/emit.py            finding_event(), summary_event(), write_events()
src/eslabon/cli.py             main()
schema/event.schema.json       docs/event-schema.md
tests/builders.py              make_tar(), make_zip(), payload helpers
tests/test_*.py
corpus/legit.toml  scripts/update_top_lists.py  scripts/measure_fp.py
scripts/measure_typosquat.py  scripts/make_logtest_samples.py
integrations/wazuh/eslabon_v2_rules.xml  agent-ossec.conf.snippet  README.md
  (R51: rules file renamed from local_rules.xml; logtest samples generated on demand,
  never committed. The 70 KB experiment script is docs/evidence/e7/scripts/exp_e7.py,
  not scripts/oversize_line.py, ruling R55)
integrations/sigma/eslabon_v2_known_malicious.yml  integrations/sigma/MAPPING.md
docs/measurements.md  docs/roadmap.md  docs/evidence/e7/
```

## Shared interfaces (model.py)

Every task consumes these. Define them in Task 2 exactly as written.

```python
@dataclass(frozen=True)
class Limits:
    max_download: int = 50 * 2**20
    max_total: int = 200 * 2**20
    max_file: int = 10 * 2**20
    max_members: int = 5000
    max_zip_cd: int = 5000 * (46 + 512)
    worker_timeout_s: float = 120.0
    yara_timeout_s: int = 10

@dataclass(frozen=True)
class Member:   index: int; path: str; data: bytes   # path normalised; index = order in archive
@dataclass(frozen=True)
class Anomaly:  kind: str; path_hex: str; detail: str
# Anomaly kinds (full set as built, see src/eslabon/model.py): traversal, absolute_path,
# link_skipped, zip_symlink (R14), duplicate_name, encrypted_member,
# unsupported_compression, bad_member, unknown_type (R18), weak_hash_sha1, no_metadata,
# ambiguous_metadata (R26), special_member, overlapped_entry (R24), dir_with_content
# (R28), bad_package_json (R33), package_json_too_deep (R34), identity_mismatch (R42),
# no_identity (R47), temp_leftover (R49). encrypted_member, unsupported_compression,
# bad_member, package_json_too_deep and no_identity make the status "incomplete".
@dataclass(frozen=True)
class Finding:  rule_id: str; file: str; member_index: int; line: int; snippet: str;
                match_count: int; name_hex: str      # member_index = -1 for package-level rules
@dataclass(frozen=True)
class PackageRef: name: str | None; version: str | None; ecosystem: str; archive_sha256: str
# For name==version the name/version come from the user. For a local archive they are read
# from inside it (sdist PKG-INFO, wheel *.dist-info/METADATA, npm package/package.json) and
# are attacker-controlled; if absent: name=None, anomaly no_metadata. (As built, R42/R46/
# R47: ESL-005/006 then use the name and version from the archive's file name; with no
# name at all, anomaly no_identity -> status incomplete, and osv_status unavailable
# (skipped under --offline).)
@dataclass(frozen=True)
class ScanContext: rules: "yara.Rules"; limits: Limits; pkg: PackageRef
# Every analyser has the signature  Callable[[Member, ScanContext], list[Finding]]
@dataclass
class ScanResult:
    status: str             # ok|timeout|limits_exceeded|parse_error|hash_mismatch|fetch_error|incomplete|osv_unavailable
    findings: list[Finding]; anomalies: list[Anomaly]
    files_scanned: int = 0; bytes_read: int = 0
    osv_status: str = "skipped"   # ok|unavailable|skipped
    duration_ms: int = 0; error: str | None = None

class LimitsExceeded(Exception): ...
class ParseError(Exception): ...
class FetchError(Exception): ...
class HashMismatch(Exception): ...
```

---

## Stage E0: Base

**Exit condition:**
- `pytest` and `ruff check` are both green.
- `git show --stat HEAD` contains no file matched by `.gitignore`.

### Task 1: Project skeleton

**Prerequisite. The user does this, because it installs software on the host.** In the
Claude Code prompt, run:

```
! winget install -e --id Python.Python.3.13
```

Then check it with `py -3.13 --version`. The expected output is `Python 3.13.x` with x ≥ 6,
the version that contains the CVE-2025-8194 fix.

**Files:**
- Create: `pyproject.toml`, `.gitattributes`, `LICENSE` (Apache-2.0 text),
  `src/eslabon/__init__.py`, `src/eslabon/__main__.py`
- Test: `tests/test_smoke.py`

**`pyproject.toml` must pin:**
- `requires-python = ">=3.13"`, `dependencies = ["yara-python==4.5.4"]`, and the extra
  `[project.optional-dependencies] dev = ["pytest", "ruff", "jsonschema"]`.
- `[project.scripts] eslabon = "eslabon.cli:main"`.
- `[tool.pytest.ini_options]`: `testpaths = ["tests"]` and `markers = ["network: hits real APIs"]`.
  Make `addopts = "-m 'not network'"` the default.
- `[tool.ruff.lint] select = ["E","F","I","B","S"]`. The tests are exempt from `S101`
  (assert) and nothing else. `scripts/measure_fp.py` is exempt from `S404` and `S603`: it
  launches eslabon itself as a subprocess.

**`.gitattributes`:** `* text=auto`, `*.jsonl text eol=lf`, `*.yar text eol=lf`,
`*.xml text eol=lf`.

- [ ] **Step 1:** Create the venv with `py -3.13 -m venv .venv`. This prompts for
  permission, which is expected. Then install with `.venv/Scripts/pip.exe install -e .[dev]`.
  Expected: `Successfully installed … yara-python-4.5.4`.
- [ ] **Step 2:** Write `tests/test_smoke.py::test_version_and_yara`. It asserts
  `eslabon.__version__ == "0.1.0"` and `yara.__version__.startswith("4.5")`. Run it and
  expect it to FAIL (no package yet).
- [ ] **Step 3:** Create the package files. Run `.venv/Scripts/python.exe -m pytest` and
  expect `1 passed`. Run `.venv/Scripts/python.exe -m ruff check .` and expect
  `All checks passed!`.
- [ ] **Step 4:** Commit with `chore: project skeleton (Python 3.13, yara-python, ruff S rules)`.

### Task 2: Shared model and rule catalog

**Files:**
- Create: `src/eslabon/model.py` (exactly the interfaces above), `src/eslabon/catalog.toml`,
  `src/eslabon/catalog.py`
- Test: `tests/test_catalog.py`

**Interfaces produced:**
- `Rule` is a frozen dataclass with these fields: `id`, `name`, `severity: int`,
  `wazuh_level: int`, `techniques: list[str]`, `technique_names: list[str]`,
  `tactics: list[str]`, `tactic_names: list[str]`, `action: str`, `residual_gap: str`,
  `detect: str`.
- `load_catalog() -> dict[str, Rule]` reads the TOML with `tomllib` through
  `importlib.resources`.

**Values to copy verbatim from §5** (catalog fields `id / name / severity / wazuh_level /
techniques`):

| id | name | severity | wazuh_level | techniques |
|---|---|---|---|---|
| ESL-001 | pypi-install-exec | 8 | 11 | T1546.016, T1059.006 |
| ESL-002 | npm-install-script-exec | 8 | 11 | T1546.016, T1059.007 |
| ESL-003 | encoded-exec | 9 | 12 | T1027.013, T1140 |
| ESL-004 | secret-exfil | 9 | 12 | T1552.001, T1041 |
| ESL-005 | typosquat | 5 | 7 | T1195.001 |
| ESL-006 | known-malicious | 10 | 13 | T1195.001 |

Each rule also has `wazuh_mitre: list[str]`. It holds the IDs written into the Wazuh XML.
It starts equal to `techniques` and is changed to a parent technique only if Task 18's
logtest shows that Wazuh's v13.1 database lacks a sub-technique (design §7). Tactic IDs
and names use v19.2 (TA0005 = "Stealth"). Use the per-technique table in the
research notes of §5. The mitigation fields (*action → residual gap → detect*) are
non-empty English text, each ≤ 300 characters. The residual gaps listed in §5 go into
`residual_gap` verbatim in substance.

- [ ] **Step 1:** Write the failing tests:
  - `test_six_rules_with_spec_values` is parametrised over the table and checks the ID, the
    name, the severity, the level and the techniques.
  - `test_no_level_15`
  - `test_mitigation_triplet_present_and_short`
  - `test_names_and_ids_align` (the lengths of `technique_names` and `techniques` match, and
    the same holds for tactics).
- [ ] **Step 2:** Run `pytest tests/test_catalog.py -v` and expect a FAIL (no module).
- [ ] **Step 3:** Implement `model.py`, `catalog.toml` and `catalog.py`.
- [ ] **Step 4:** Run it again and expect all tests to PASS. Then run `ruff check .`.
- [ ] **Step 5:** Commit with `feat: shared model and rule catalog (ESL-001..006)`.

---

## Stage E1: Hostile reading

**Exit condition:**
- Every test in `tests/test_sanitize.py`, `tests/test_archive_tar.py`,
  `tests/test_archive_zip.py` and `tests/test_worker.py` passes.
- A no-disk-write assertion holds in every archive test.
- The `security-review` skill, run on the E1 diff, reports no open finding.

### Task 3: Sanitising attacker-controlled text

**Files:** Create `src/eslabon/sanitize.py`. Test: `tests/test_sanitize.py`.

**Interfaces produced:**
- `clean_text(raw: bytes | str, max_len: int = 1024) -> str` decodes bytes as UTF-8 with
  `errors="replace"`. It then strips C0 and C1 controls except `\t`, ANSI escape sequences,
  NUL, and bidi controls U+202A–U+202E and U+2066–U+2069. It truncates to `max_len`
  characters after decoding.
- `to_hex(raw: str) -> str` returns the UTF-8 bytes as lowercase hex.

- [ ] **Step 1:** Write the failing tests:
  - `test_strips_newline_ansi_bidi_nul` checks that
    `clean_text("a\nb\x1b[31mc‮d\x00e") == "abcde"`.
  - `test_truncates_after_decoding_never_splits_utf8` checks that
    `clean_text("é"*2000, 1024) == "é"*1024`.
  - `test_invalid_utf8_replaced` checks that `clean_text(b"\xff\xfeok")` ends with `"ok"`.
  - `test_to_hex_roundtrip` checks that
    `bytes.fromhex(to_hex("../x")).decode() == "../x"`.
- [ ] **Step 2:** Run the tests and expect a FAIL.
- [ ] **Step 3:** Implement. Run the tests and expect a PASS.
- [ ] **Step 4:** Commit with `feat: sanitise attacker-controlled names and snippets`.

### Task 4: Streaming tar reader

**Files:**
- Create: `src/eslabon/archive.py`, `tests/builders.py`
- Test: `tests/test_archive_tar.py`

**Interfaces:**
- **Consumes:** `Limits`, `Member`, `Anomaly`, `LimitsExceeded` and `ParseError` from
  `model`, and `to_hex` from Task 3.
- **Produces:** `iter_members(path: Path, ecosystem: str, limits: Limits, anomalies: list[Anomaly]) -> Iterator[Member]`.
  It yields regular files only. Anomalies are appended to the list as a side effect. It
  raises `LimitsExceeded` or `ParseError`.
- **Also produces, in `tests/builders.py`:**
  - `TarItem(name: str, data: bytes = b"", type: str = "file", linkname: str = "", pax: dict | None = None)`
  - `make_tar(items: list[TarItem], compression: str = "gz") -> bytes`, where compression is
    `"gz"`, `"bz2"` or `""`.

**Decisions:**
- Detect the format by magic bytes, not by extension: `1f 8b` is gzip, `BZh` is bz2,
  `PK\x03\x04` goes to Task 5, and anything else is tried as a plain tar.
- gzip is read with `zlib.decompressobj(wbits=31)` and bz2 with `bz2.BZ2Decompressor`.
  Plain tar is read raw. All three are wrapped in a `_CountingReader` with `.read(n)`, which
  raises `LimitsExceeded` once `limits.max_total` bytes have passed. Its total is
  `ScanResult.bytes_read`.
- Concatenated members are legitimate and are looped over: `unused_data` starting with
  `1f 8b` or `BZh` starts a new member. Trailing zero bytes are legitimate padding. Any
  other trailing bytes raise `ParseError`.
- `files_scanned` is the number of regular members yielded.
- Open with `tarfile.open(fileobj=reader, mode="r|")`.
- Read each member with `extractfile(m).read(limits.max_file + 1)`. If it is longer than
  `max_file`, raise `LimitsExceeded`.
- Normalisation: replace `\` with `/`, collapse `//` and `./`, and for npm strip the first
  path component. A name that contains a `..` component or starts with `/` or `X:` is
  recorded as an anomaly (`traversal` or `absolute_path`) and its member is still scanned
  under the normalised name.
- Symlinks and hardlinks are never read. They become an anomaly (`link_skipped`) and count
  toward `max_members`.
- Duplicate names: an anomaly (`duplicate_name`) is recorded and every copy is yielded.
  (Superseded by ruling R29 during execution: there is NO last-copy-wins; every copy is
  scanned and every copy's findings are reported. See docs/event-schema.md.)

- [ ] **Step 1:** Write the failing tests. Each one runs inside `tmp_path`, `chdir`s there,
  and finally asserts that `os.listdir(tmp_path)` contains only the input archive (no disk
  writes).
  - `test_regular_files_yielded_normalised`: npm `package/index.js` is yielded as `index.js`.
  - `test_traversal_name_flagged_nothing_written`: `../../evil.py` gives an anomaly of kind
    `traversal`.
  - `test_absolute_and_drive_paths_flagged`
  - `test_symlink_and_hardlink_skipped_and_counted`: a link to `/etc/passwd` is not yielded
    and is recorded as `link_skipped`.
  - `test_duplicate_name_flagged`
  - `test_member_cap`: 5,001 empty files raise `LimitsExceeded`.
  - `test_per_file_cap`: one file of `max_file + 1` bytes raises `LimitsExceeded`.
  - Bomb tests pass a small `Limits(max_total=1 MiB, max_file=256 KiB)` so they stay fast
    and use little memory. What is being tested is the cap, not the default value.
  - `test_gzip_bomb`: 2 MiB of zeros, a few KB compressed, raises `LimitsExceeded`.
  - `test_pax_header_bomb`: a hand-crafted ustar `x` header whose size field declares
    2 MiB, followed by zeros, raises `LimitsExceeded`. It is not built with tarfile's
    writer, which would make several in-memory copies.
  - `test_gzip_trailing_garbage_parse_error`
  - `test_concatenated_gzip_members_and_zero_padding_ok`
  - `test_plain_tar_counted_against_max_total`
  - `test_bz2_supported`
  - `test_empty_archive_yields_nothing` (Review Focus 3).
- [ ] **Step 2:** Run `pytest tests/test_archive_tar.py -v` and expect all to FAIL.
- [ ] **Step 3:** Implement `iter_members` for tar.
- [ ] **Step 4:** Run the tests and expect all to PASS. Check that peak memory in the bomb
  tests stays bounded: the test must finish without a `MemoryError`.
- [ ] **Step 5:** Commit with `feat: streaming capped tar reader with anomaly recording`.

### Task 5: Zip and wheel reader

**Files:** Modify `src/eslabon/archive.py` and `tests/builders.py` (add `make_zip`). Test:
`tests/test_archive_zip.py`.

**Decisions:**
- Before calling `zipfile.ZipFile`, locate the EOCD (signature `PK\x05\x06`, searched in the
  last 65,557 bytes) or the ZIP64 EOCD with `struct`. Reject with `LimitsExceeded` if it
  declares more than `max_members` entries or a central directory larger than `max_zip_cd`
  bytes.
- Read each member with `zf.open(info).read(max_file + 1)`. Catch per-member errors and
  record them as anomalies: `BadZipFile` becomes `bad_member`, `RuntimeError` becomes
  `encrypted_member`, `NotImplementedError` becomes `unsupported_compression`.
- The download cap (≤ 50 MiB) bounds the whole-file read.

- [ ] **Step 1:** Write the failing tests:
  - `test_wheel_members_yielded`
  - `test_zip_declaring_million_entries_rejected_before_parse`: a hand-built EOCD with
    `total_entries=1_000_000` raises `LimitsExceeded`. Assert that `zipfile.ZipFile` was
    never called by monkeypatching it to fail.
  - `test_encrypted_member_is_anomaly_not_crash`: set the encryption flag bit 0x1 by hand.
  - `test_unsupported_compression_is_anomaly`: compression method 9 (Deflate64).
  - `test_zip_traversal_flagged_nothing_written`
- [ ] **Step 2:** Run the tests and expect a FAIL. **Step 3:** Implement. **Step 4:** Run
  the tests and expect a PASS.
- [ ] **Step 5:** Commit with `feat: zip/wheel reader with EOCD pre-check`.

### Task 6: Isolated worker with wall-clock timeout

**Files:** Create `src/eslabon/worker.py`. Test: `tests/test_worker.py`.

**Interfaces produced:**
`run_isolated(fn: Callable[..., ScanResult], args: tuple, timeout_s: float) -> ScanResult`.

**Decisions:**
- Use `multiprocessing.get_context("spawn")` and a `Queue`.
- The parent polls `q.get(timeout=0.2)` in a loop **before** `p.join()`. The loop stops when
  a result arrives, when the child has died (`not p.is_alive()`), or at the deadline.
  - A result arrives: `join()` and return it.
  - The child died without a result: `status="parse_error"`, with
    `error=f"worker exited with code {p.exitcode}"`. This is reported immediately, not
    after the timeout.
  - The deadline passes: `terminate()`, `join(5)`, and return
    `ScanResult(status="timeout", findings=[], anomalies=[], error="worker timeout")`.
- The child target is module-level. `fn` must also be module-level, which spawn requires.

- [ ] **Step 1:** Write the failing tests. Both helper functions are defined at module level
  in the test file.
  - `test_returns_child_result`
  - `test_timeout_gives_timeout_status_never_ok`: a function that sleeps 30 s, with
    `timeout_s=2`, gives `status == "timeout"`, and the call takes less than 10 s.
  - `test_child_crash_is_parse_error_not_ok_and_fast`: a function that calls `os._exit(3)`,
    with `timeout_s=60`, gives `status == "parse_error"`, `"3"` in `error`, and the call
    takes less than 10 s.
- [ ] **Step 2:** Run the tests and expect a FAIL. **Step 3:** Implement. **Step 4:** Run
  the tests and expect a PASS.
- [ ] **Step 5:** Commit with `feat: isolated worker with wall-clock timeout`.
- [ ] **Step 6 (E1 gate):** Run the `security-review` skill on `git diff <E0 commit>..HEAD`.
  Fix every finding with a test first, then re-run it. E1 is closed only when it is clean.

---

## Stage E2: Event

**Exit condition:**
- `eslabon scan <fixture>.tgz --ecosystem npm --out <tmp>/events.jsonl` writes a summary
  line that validates against `schema/event.schema.json`.
- `tests/test_emit.py::test_every_line_under_64k` passes.
- `docs/event-schema.md` states `ecs.version`.

### Task 7: Schema and emitter

**Files:**
- Create: `schema/event.schema.json` (JSON Schema draft 2020-12), `docs/event-schema.md`,
  `src/eslabon/emit.py`
- Test: `tests/test_emit.py`

**Interfaces:**
- **Consumes:** `Finding`, `ScanResult`, `PackageRef`, `Rule`, `clean_text`, `to_hex`.
- **Produces:**
  - `ECS_VERSION: str` and `SCHEMA_VERSION = "1.0"`.
  - `finding_event(f: Finding, rule: Rule, pkg: PackageRef, scan_id: str, now: datetime) -> dict`
  - `summary_event(r: ScanResult, pkg: PackageRef, scan_id: str, now: datetime) -> dict`
  - `write_events(events: Iterable[dict], out: Path) -> int` returns the number of lines.

**Decisions:**
- Set `ECS_VERSION` to the latest release at <https://github.com/elastic/ecs/releases> when
  this task is done. Record it in `docs/event-schema.md` together with the date you checked
  it.
- Cap `evidence.file` and every other emitted path at 512 characters, and `name_hex` and
  `path_hex` at 1,024 characters, both with `clean_text`.
- Field layout is exactly §6.
- `json.dumps(..., ensure_ascii=True, separators=(",", ":"))`.
- Open the file in append mode, `encoding="utf-8"`, `newline="\n"`. Create the parent
  directory if it does not exist.
- The schema must require these fields: `@timestamp`, `ecs.version`, `event.kind`,
  `event.module` (const `eslabon`), `event.dataset` (enum `eslabon.finding` or
  `eslabon.scan`), `eslabon.schema_version`, `package.name` and `eslabon.ecosystem` (enum
  `pypi` or `npm`). For findings it also requires `rule.id` (pattern `^ESL-00[1-6]$`),
  `event.severity` (an integer from 1 to 10), the string array `threat.technique.id` and
  `eslabon.evidence.*`. Summaries require `eslabon.scan.status` with the enum from §6.

- [ ] **Step 1:** Write the failing tests:
  - `test_finding_event_validates`
  - `test_summary_event_validates_each_status` is parametrised over the 8 statuses.
  - `test_every_line_under_64k`: a `Finding` with a 10 MiB snippet still emits a line under
    `MAX_LINE_BYTES` (65,536 when planned; 65,000 since ruling R54).
  - `test_megabyte_path_capped` (Review Focus 3): a 1 MB `file` and `name_hex`, and an
    `Anomaly` with a 1 MB `path_hex`, all give lines under `MAX_LINE_BYTES`.
  - `test_no_bom_and_lf_only`
  - `test_append_not_truncate` (Review Focus 4).
  - `test_missing_parent_dir_created`
  - `test_arrays_contain_only_strings` walks the whole event.
- [ ] **Step 2:** Run the tests and expect a FAIL. **Step 3:** Implement. **Step 4:** Run
  the tests and expect a PASS.
- [ ] **Step 5:** Commit with `feat: ECS event schema and JSON Lines emitter`.

### Task 8: Scan orchestration and CLI for local archives

**Files:** Create `src/eslabon/scan.py` and `src/eslabon/cli.py`. Test: `tests/test_cli.py`.

**Interfaces produced:**
- `analyze_archive(path: Path, pkg: PackageRef, limits: Limits) -> ScanResult` is
  module-level, so the worker can run it.
  - It compiles the rules once per worker and builds a `ScanContext`.
  - In this task it only reads members and counts them. Analysers are plugged in from
    Task 9 onwards through a module-level list
    `ANALYZERS: list[Callable[[Member, ScanContext], list[Finding]]]`.
  - It reports the findings of every copy of a duplicate name (ruling R29; no suppression).
  - It maps `LimitsExceeded` to `limits_exceeded` and `ParseError` to `parse_error`.
- `read_metadata(path: Path, ecosystem: str, limits: Limits) -> tuple[str | None, str | None]`
  reads the name and version of a local archive from inside it (see `PackageRef` in the
  shared interfaces). It runs inside the worker, which returns them in a field of the
  result that `cli` copies into the `PackageRef` used for ESL-005 and ESL-006.
- `main(argv: list[str] | None = None) -> int`.
  - Usage: `eslabon scan TARGET [--ecosystem {pypi,npm}] [--out PATH] [--offline]`.
  - The default `--out` is `./events.jsonl`.
  - `.whl` implies `pypi`. Any other local file without `--ecosystem` exits 2.
  - It computes `archive_sha256` and generates `scan_id = uuid4().hex`.

- [ ] **Step 1:** Write the failing tests:
  - `test_scan_clean_archive_exit_0_and_summary_valid`
  - `test_exit_code_2_wins_over_1` monkeypatches `ANALYZERS` to return one finding and
    forces `status="timeout"`. Expect exit 2 with both lines emitted.
  - `test_limits_exceeded_exit_2`
  - `test_missing_file_exit_2_one_line_stderr_no_traceback` (Review Focus 5).
  - `test_unknown_extension_without_ecosystem_exit_2`
  - `test_two_scans_append_to_same_out` (Review Focus 4).
  - `test_duplicate_member_every_copy_reported`
  - `test_local_archive_over_max_download_refused_before_open`
  - `test_local_metadata_read_or_no_metadata_anomaly`
- [ ] **Step 2:** Run the tests and expect a FAIL. **Step 3:** Implement. **Step 4:** Run
  the tests and expect a PASS.
- [ ] **Step 5:** Manual check of the E2 exit condition:
  `.venv/Scripts/python.exe -m eslabon scan <tmp>/clean.tgz --ecosystem npm --out <tmp>/e.jsonl`.
  Then validate that file with a one-off `python -c` that uses `jsonschema`, and paste the
  output.
- [ ] **Step 6:** Commit with `feat: scan orchestration and CLI for local archives`.

---

## Stage E3: Code heuristics

**Exit condition:** for each of ESL-001 to ESL-004, a positive test and a near-miss test
pass, and each was **seen failing first**. Record the red run's output in the commit
message body.

### Task 9: YARA engine and ESL-003 encoded-exec

**Files:**
- Create: `src/eslabon/yara_engine.py`, `src/eslabon/rules/esl003.yar`
- Test: `tests/test_esl003.py`

**Interfaces produced:**
- `compile_rules() -> yara.Rules` compiles every `rules/*.yar` with `error_on_warning=True`,
  each file in its own namespace. Every rule carries `meta: esl_id = "ESL-00N"`.
- `scan_member(m: Member, ctx: ScanContext) -> list[Finding]` returns one `Finding` per
  matched `esl_id`.
  - It takes the first string match's offset. `line` is the count of `\n` before it, plus
    one.
  - The snippet is `clean_text(data[max(0, off-120): off+200])`.
  - `match_count` is the total number of string instances.
  - It calls `rules.match(data=..., timeout=limits.yara_timeout_s)`, and a
    `yara.TimeoutError` becomes a `LimitsExceeded`.
- Register it in `scan.ANALYZERS`. Rules are compiled once per worker.

**ESL-003 rule:** evaluator and decoder adjacent, using bounded gaps only.
- Python: `(exec|eval|compile)\s*\(\s*.{0,50}(b64decode|decodebytes|bytes\.fromhex|zlib\.decompress)`
- JavaScript: `(eval|Function)\s*\(\s*.{0,50}(atob\s*\(|Buffer\.from\([^)]{0,50}['"]base64)`

- [ ] **Step 1:** Write the failing tests:
  - `test_py_exec_b64_fires`: a `setup.py` built from concatenated tokens.
  - `test_js_eval_atob_fires`
  - `test_b64_data_without_evaluator_silent`: a base64 PNG in a `.py` file.
  - `test_rules_compile_with_error_on_warning`
  - `test_binary_member_no_crash` (Review Focus 1): random bytes plus an `.so` header.
- [ ] **Step 2:** Run the tests and expect a FAIL. **Step 3:** Implement. **Step 4:** Run
  the tests and expect a PASS.
- [ ] **Step 5:** Commit with `feat: YARA engine and ESL-003 encoded-exec`.

### Task 10: ESL-001 pypi-install-exec

**Files:** Create `src/eslabon/rules/esl001.yar`. Test: `tests/test_esl001.py`.

The rule applies only to the `setup.py` that pip would run: normalised path `setup.py`, or
`<single top-level dir>/setup.py` in an sdist. This is enforced in `scan_member`, which
applies `esl001` namespace matches only to that path. Add
`test_nested_or_prefixed_setup_py_silent`, covering `pkg/tests/data/setup.py` and
`foo_setup.py`. It fires on a
network primitive (`urlopen`, `urllib.request`, `requests.(get|post)`, `socket.socket`,
`http.client`) **or** on `subprocess`/`os.system` followed within 200 bytes by
`curl|wget|powershell|https?://`.

- [ ] **Step 1:** Write the failing tests:
  - `test_setup_urlopen_fires`
  - `test_setup_subprocess_curl_fires`
  - `test_requests_style_version_exec_silent`: `exec(open('src/x/__version__.py').read(), about)`.
  - `test_pg_config_subprocess_silent`: `subprocess.check_output(['pg_config','--version'])`.
  - `test_urlopen_outside_setup_py_silent_for_esl001`
- [ ] **Steps 2–5:** run red, implement, run green, commit with `feat: ESL-001 pypi-install-exec`.

### Task 11: ESL-002 npm-install-script-exec

**Files:** Create `src/eslabon/npm_scripts.py` and `src/eslabon/rules/esl002.yar`. Test:
`tests/test_esl002.py`.

**Interfaces produced:** `scan_package_json(m: Member, ctx: ScanContext) -> list[Finding]`.
It applies only to the normalised path `package.json`. It parses the file with `json`,
takes `scripts.preinstall`, `scripts.install` and `scripts.postinstall`, and matches the
`esl002` namespace against each script string. Evidence `line` is the line of the script
key in the file. Register it in `ANALYZERS`.

The rule fires on `curl|wget|Invoke-WebRequest|iwr|certutil|bitsadmin`, on a pipe to
`sh|bash|powershell`, on `node\s+(-e|--eval)`, on `powershell\s+-(e|enc|encodedcommand)`,
or on `https?://`.

- [ ] **Step 1:** Write the failing tests:
  - `test_postinstall_curl_pipe_sh_fires`
  - `test_preinstall_node_eval_fires`
  - `test_node_install_js_silent` (the esbuild shape)
  - `test_node_gyp_rebuild_silent`
  - `test_husky_install_silent`
  - `test_malformed_package_json_is_anomaly_not_crash`
- [ ] **Steps 2–5:** run red, implement, run green, commit with `feat: ESL-002 npm-install-script-exec`.

### Task 12: ESL-004 secret-exfil

**Files:** Create `src/eslabon/rules/esl004.yar`. Test: `tests/test_esl004.py`.

The rule is a condition of `any of ($cred*) and any of ($sink*)`, using the exact patterns
in the §5 table row for ESL-004.
- The public-IPv4 check is done in Python, in `scan_member`, after the YARA match on
  `https?://\d{1,3}(\.\d{1,3}){3}`. It uses `ipaddress.ip_address(x).is_global`.
- If no sink survives that filter, there is no finding.

- [ ] **Step 1:** Write the failing tests:
  - `test_ssh_key_plus_discord_webhook_fires`
  - `test_env_dump_plus_telegram_fires`
  - `test_env_dump_plus_public_ip_url_fires`
  - `test_botocore_shape_silent`: `.aws/credentials` plus `http://169.254.169.254`.
  - `test_node_env_stringify_silent`: `JSON.stringify(process.env.NODE_ENV)` plus a normal
    URL.
  - `test_toast_substring_silent`
  - `test_private_ip_url_silent`: `http://10.0.0.5`.
- [ ] **Steps 2–5:** run red, implement, run green, commit with `feat: ESL-004 secret-exfil`.

---

## Stage E4: Context and reputation

**Exit condition:**
- Every test passes.
- `.venv/Scripts/python.exe -m pytest -m network` passes.
- `eslabon scan requests==2.32.3 --ecosystem pypi --offline --out <tmp>/e.jsonl` exits 0
  or 1 (any finding gets triaged in E5), never 2. Its `file.hash.sha256` must equal PyPI's
  published digest. Paste the output. (Since ruling R54 the archive hash is
  `eslabon.archive.sha256`; E4 was verified on the old field name.)

### Task 13: ESL-005 typosquat and top lists

**Files:**
- Create: `scripts/update_top_lists.py`, `src/eslabon/data/top_pypi.json`,
  `src/eslabon/data/top_npm.json`, `src/eslabon/typosquat.py`
- Test: `tests/test_typosquat.py`

**Decisions:**
- `update_top_lists.py` downloads the PyPI list from
  `https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json`. For npm it uses
  the source chosen here; check `npm-high-impact` first and record why it was chosen or
  rejected.
- It writes `{"source": url, "retrieved": "YYYY-MM-DD", "names": [...top 6000 in rank order]}`.
  It downloads JSON lists only, never a package.

**Interfaces produced:**
- `normalize(name: str, ecosystem: str) -> str` follows PEP 503 for PyPI
  (`re.sub(r"[-_.]+", "-", n).lower()`). For npm it lowercases and strips `@scope/`.
- `distance(a: str, b: str) -> int` is the Damerau-Levenshtein distance, optimal string
  alignment variant.
- `check(name: str, ecosystem: str) -> Finding | None` follows §5 exactly.
  - It exempts the **full** name if it is in the top 5,000.
  - Targets are the top 1,000.
  - The threshold is 1 if `len(normalized) <= 5`, else 2.
  - Distance 0 after stripping a scope is scope confusion.
  - The evidence is `file="<package name>"`, `line=0`, and the snippet
    `"<name> ~ <target> (distance N)"`.
- It is wired into `analyze_archive` once per scan, not per member.

- [ ] **Step 1:** Write the failing tests:
  - `test_reqeusts_flagged_against_requests`
  - `test_top_names_never_flagged`, parametrised over `ms`, `qs`, `ws`, `chalk`, `chai`,
    `numpy`, `numba`, `boto`, `boto3` and `@babel/core`.
  - `test_scope_confusion_evil_react`
  - `test_pep503_normalisation`: `Typing_Extensions` becomes `typing-extensions`
    (Review Focus 2).
  - `test_short_name_threshold_is_1`
  - `test_distance_transposition_is_1`
- [ ] **Steps 2–5:** run red, implement, run green, then commit the code together with the
  two data files: `feat: ESL-005 typosquat with dated top lists`.

### Task 14: ESL-006 known-malicious (OSV)

**Files:** Create `src/eslabon/osv.py` and `tests/data/osv/*.json` (recorded responses).
Test: `tests/test_osv.py`.

**Interfaces produced:**
- Signature: `query_malicious(name: str, version: str | None, ecosystem: str, opener: Callable | None = None, timeout_s: float = 15) -> tuple[str, list[str]]`.
- It returns `("ok", [MAL ids])` or `("unavailable", [])`.
- Request: `POST https://api.osv.dev/v1/query` with
  `{"package":{"name":…,"ecosystem":"PyPI"|"npm"},"version":…}`.
- It keeps only IDs that start with `MAL-` and have no `withdrawn` field.
- It is called by `cli.main` in the parent process, after the worker returns, unless
  `--offline`.
- Each ID becomes a `Finding("ESL-006", file="<osv>", line=0, snippet=<id + summary>, …)`.
- `osv_status="unavailable"` sets `status="osv_unavailable"`, which exits 2.

- [ ] **Step 1:** Write the failing tests, all using recorded responses:
  - `test_mal_record_becomes_finding`: the shape of `MAL-2025-28954`.
  - `test_cve_and_ghsa_ignored`
  - `test_withdrawn_ignored`
  - `test_network_error_is_unavailable_exit_2`
  - `test_offline_skips_and_records_skipped`
  - `@pytest.mark.network test_real_api_requests_2_31_0_has_no_mal`
- [ ] **Steps 2–5:** run red, implement, run green, commit with `feat: ESL-006 OSV known-malicious`.

### Task 15: Registry fetch for `name==version`

**Files:** Create `src/eslabon/fetch.py` and modify `src/eslabon/cli.py`. Test:
`tests/test_fetch.py`.

**Interfaces produced:**
- `Artifact` is a frozen dataclass with `url: str`, `filename: str`, `hash_alg: str`
  (`sha256`, `sha512` or `sha1`) and `hash_value: str`.
- `resolve(name: str, version: str, ecosystem: str, opener=None) -> Artifact` implements the
  wheel and sdist choice and the scoped-name `%2f` encoding from §4.
- `download(a: Artifact, dest: Path, limits: Limits, opener=None) -> tuple[Path, list[Anomaly]]`:
  - It writes **only** the downloaded archive, to a `tempfile.mkdtemp()` directory outside
    the repo.
  - It counts bytes as they arrive and raises `LimitsExceeded` above `max_download`.
  - It verifies the hash and raises `HashMismatch`. A sha1 artifact adds the anomaly
    `weak_hash_sha1`.
- `ALLOWED_HOSTS = {"pypi.org", "files.pythonhosted.org", "registry.npmjs.org"}` is checked
  on the initial URL and on every redirect, through a custom `HTTPRedirectHandler`. Only
  `https` is accepted, and the socket timeout is 30 s.
- `cli` parses `name==version` with `^(@[a-z0-9._-]+/)?[A-Za-z0-9._-]+==[A-Za-z0-9.+!_-]+$`.
  Anything else that is not an existing path exits 2.

- [ ] **Step 1:** Write the failing tests, using fake openers:
  - `test_pypi_prefers_sdist_then_py3_none_any_then_cp313_manylinux`
  - `test_npm_scoped_name_encoded`
  - `test_npm_sha1_only_accepted_with_anomaly`
  - `test_hash_mismatch_exit_2`
  - `test_redirect_to_other_host_rejected`
  - `test_redirect_to_http_rejected`
  - `test_download_over_cap_rejected_ignoring_content_length`
  - `test_bad_target_syntax_exit_2`, parametrised over `requests=2`, `requests==` and
    `==1.0` (Review Focus 5).
  - `test_django_uppercase_resolves_url` (Review Focus 2).
  - `@pytest.mark.network test_real_requests_2_32_3_hash_verified`
- [ ] **Steps 2–4:** run red, implement, run green. Then run the E4 manual command and paste
  its output.
- [ ] **Step 5:** Commit with `feat: registry fetch with hash verification and redirect allowlist`.

---

## Stage E5: False positives

**Exit condition:** `docs/measurements.md` contains:
- the table of fully scanned, incomplete and false positives over 200 packages;
- every false positive, either fixed by a rule change (with its new near-miss test) or
  listed as a known false positive;
- the ESL-005 count on ranks 5,001–6,000 for both ecosystems;
- the date, the Eslabon commit and the corpus file hash.

### Task 16: Corpus and measurement scripts

**Files:**
- Create: `corpus/legit.toml` (`[[package]] ecosystem name version`, top 100 of each list
  with the latest version pinned when generated), `scripts/measure_fp.py`,
  `scripts/measure_typosquat.py`, `docs/measurements.md`

**Decisions:**
- `measure_fp.py` runs `eslabon scan name==version --ecosystem E --out <tmp>/fp.jsonl` as a
  subprocess per package, **on the host**, because these are legitimate packages. It
  aggregates by status and rule and prints a Markdown table.
- `measure_typosquat.py` calls `typosquat.check` on names ranked 5,001–6,000, by name only.
- **There are no allowlists by package name.**

- [ ] **Step 1:** Generate `corpus/legit.toml` from the top lists. Commit it with
  `chore: pinned legit corpus (top 100 PyPI + top 100 npm)`.
- [ ] **Step 2:** Run `measure_fp.py` and paste the table.
- [ ] **Step 3:** Handle each false positive. Use `superpowers:systematic-debugging` to find
  which pattern matched and why. Then write a near-miss test from the real snippet,
  rewritten synthetically, watch it fail, fix the rule, and re-run the full suite and the
  measurement. If a false positive cannot be removed without blinding the rule, list it in
  `docs/measurements.md` as known.
- [ ] **Step 4:** Run `measure_typosquat.py` and record the counts.
- [ ] **Step 5:** Commit with `docs: false-positive measurement`, with the numbers in the
  message body.

---

## Stage E6: Offline integration

**Exit condition:** `tests/test_integrations.py` passes. That file contains the
catalog↔XML consistency check, the check that the Sigma rule is valid YAML with the
required keys, and the check that every logtest sample validates against the schema.

### Task 17: Wazuh rules, agent snippet, Sigma and its translation

**Files:**
- Create: `integrations/wazuh/eslabon_v2_rules.xml` (ruling R51; planned as
  `local_rules.xml`), `integrations/wazuh/agent-ossec.conf.snippet`,
  `scripts/make_logtest_samples.py` (R51: samples generated on demand, never committed;
  planned as `integrations/wazuh/logtest-samples/*.jsonl`), `integrations/wazuh/README.md`,
  `integrations/sigma/eslabon_v2_known_malicious.yml`, `integrations/sigma/MAPPING.md`
- Test: `tests/test_integrations.py`

**Decisions:** the rules are exactly §7.
- `100300` is the parent, at level 0: `<decoded_as>json</decoded_as>`,
  `<location>events.jsonl$</location>` and
  `<field name="event.module" type="pcre2">^eslabon$</field>`.
- `100301`–`100306` each use `<if_sid>100300</if_sid>` and
  `<field name="rule.id" type="pcre2">^ESL-00N$</field>`, with the level and `<mitre>`
  taken from the catalog. Every `<field>` is `type="pcre2"` (ruling R52: in the default
  OS_Regex `\.` matches any character).
- `100310` matches `event.dataset` `^eslabon\.scan$` and status `^ok$`, at level 3.
- `100311` is the same with `negate="yes"` on the status, at level 7.
- `100306` doubles as the hand translation of the Sigma rule (ESL-006, known-malicious). `MAPPING.md` maps each Sigma field to the Wazuh `<field>` it becomes. There is no separate `100320`: one alert per event.
- Descriptions use `$(package.name)` and `$(rule.name)`; whether they render is checked in
  E7.
- `eslabon_v2` comes only from the file's enclosing `<group name="eslabon_v2,">`; no
  `<rule>` repeats it (ruling R54: a per-rule `<group>eslabon_v2,</group>`, as first
  planned here, listed the group twice in the alert's `rule.groups` in E7).
- The snippet is the single `<localfile>` from §7 with
  `<location>/var/log/eslabon/events.jsonl</location>`.
- The logtest samples are generated by running the real emitter against the fixtures, not
  hand-written.

- [ ] **Step 1:** Write the failing tests:
  - `test_xml_levels_and_mitre_match_catalog`, parsed with `xml.etree`. It compares the
    XML `<mitre>` IDs with the catalog's `wazuh_mitre`, not with `techniques`.
  - `test_rule_tree_one_alert_per_event` (Review Focus 1): a small Python model of the
    `if_sid` tree, fed each sample, asserts that exactly one leaf rule matches it.
  - `test_xml_ids_in_range_and_unique`: every ID is in 100300–100399 and none is in
    100100–100199.
  - `test_no_level_15`
  - `test_sigma_targets_esl006_and_maps_to_100306`
  - `test_logtest_samples_validate_against_schema`
- [ ] **Steps 2–4:** run red, write the files, run green.
- [ ] **Step 5:** Commit with `feat: Wazuh rules (100300-100399), agent snippet, Sigma rule (ESL-006) and its translation`.

---

## Stage E7: Lab end to end (one lab session, one writeup)

**Exit condition:** `docs/evidence/e7/` contains:
- the `wazuh-logtest` output for each sample;
- generate/collect/detect counts per `rule.id` with the commands that produced them;
- the result of the 70 KB line and BOM experiments;
- the six §11 checks, each marked confirmed or contradicted.

The counts must show N = N = N, or explain any difference. Kali must be restored to its
snapshot.

### Task 18: Lab procedure

Every `VBoxManage` call prompts for permission, which is intended. For each command, tell
the user what was run, why, and what the result showed.

- [ ] **Step 1: Snapshot.** Run `VBoxManage snapshot "kali-linux-2026.1-virtualbox-amd64" take "pre-eslabon-v2"`.
- [ ] **Step 2: Check Kali's Python.** Run `python3 --version`. 3.13 is fine. If it is 3.14,
  there is no `yara-python` wheel. Install `python3.13` from the Kali repos into a venv. If
  that package does not exist, build `yara-python==4.5.4` from its sdist inside the venv,
  which needs `build-essential` and `libssl-dev`. That is our own dependency, not an
  analysed package. Use the Linux `guestcontrol` form from `CLAUDE.md` (`--exe /bin/bash -- script.sh`,
  without repeating `bash`) and `kali`/`kali` credentials.
- [ ] **Step 3: Wazuh agent on Kali.** Commands run as `kali` go through `sudo -S`.
  - Add the Wazuh 4.x apt repository. Install with
    `sudo WAZUH_MANAGER=10.10.10.10 apt-get install -y wazuh-agent=4.14.7-1`, then run
    `sudo apt-mark hold wazuh-agent`. 4.14.8 exists, and an agent newer than its manager is
    not supported.
  - Replace the default `ossec.conf` `<localfile>`, syscheck and rootcheck blocks with the
    trimmed config: only `integrations/wazuh/agent-ossec.conf.snippet`.
  - Create `/var/log/eslabon/` owned by `kali`.
  - Enable and start the agent, then confirm it shows as `Active` in
    `/var/ossec/bin/agent_control -l` on the manager over SSH (`ssh analista@127.0.0.1 -p 2222`).
  - Note the agent ID for the clean-up.
- [ ] **Step 4: Manager.**
  - Install the rules as a **separate file**,
    `/var/ossec/etc/rules/eslabon_v2_rules.xml` (owner `wazuh`, mode 660). v1's file is
    left untouched, and removing v2 is deleting one file.
  - Set `<logall_json>yes</logall_json>` **for this session only**.
  - Run `systemctl restart wazuh-manager`.
  - Run each logtest sample through `/var/ossec/bin/wazuh-logtest` and save the output.
    Check the §11 items here: `data.rule.*` against Wazuh's own `rule.*`, array matching,
    `$(…)` interpolation, and the MITRE ID warnings.
- [ ] **Step 5: Install Eslabon on Kali.** Copy the source with `guestcontrol copyto` and
  install it with `pip install -e .` **inside a venv on Kali**. That install is of our own
  package, not of an analysed one.
- [ ] **Step 6: Generate.**
  - Build the fixture archives on Kali with `tests/builders.py`.
  - Run one scan per rule plus one clean scan, all with
    `--out /var/log/eslabon/events.jsonl`.
  - Count the lines per `rule.id` and `dataset`.
- [ ] **Step 7: Collect.** Count the matching events in
  `/var/ossec/logs/archives/archives.json` on the manager.
- [ ] **Step 8: Detect, in two places.**
  - Count `rule.groups` = `eslabon_v2` in `/var/ossec/logs/alerts/alerts.json` on the
    manager. This is what the rules engine produced.
  - Query `wazuh-alerts-*` through the dashboard console proxy (`CLAUDE.md`) with this DSL:
    ```json
    {"size":0,"query":{"bool":{"filter":[
      {"term":{"rule.groups":"eslabon_v2"}},
      {"range":{"@timestamp":{"gte":"<session start ISO8601>"}}}]}},
     "aggs":{"wazuh_rule":{"terms":{"field":"rule.id"}},
             "esl_rule":{"terms":{"field":"data.rule.id"}}}}
    ```
  - A difference between `alerts.json` and the index means the indexer rejected the
    document, for example through a mapping conflict on a `data.*` field. That counts as a
    finding, not as noise.
  - The `admin` password is given by the user in chat and never written to a file.
- [ ] **Step 9: Experiments.**
  - Run `docs/evidence/e7/scripts/exp_e7.py` to append one 70 KB line to the monitored
    `events.jsonl` (ruling R55: `scripts/oversize_line.py` was never created).
  - Then rotate the monitored file: move `events.jsonl` aside and recreate it starting with
    a UTF-8 BOM followed by one valid event. A new file at an unmonitored path would show
    nothing.
  - Record what each layer shows, including the agent's `ossec.log` warning.
- [ ] **Step 10: Clean up.**
  - Set `logall_json` back to `no` and restart the manager.
  - Stop the agent on Kali **first**: `sudo systemctl stop wazuh-agent`. A running agent
    re-enrols by itself and gets the same ID back, so a removal done while it runs is
    undone (measured in E7: `manage_agents -r 001` had to be repeated).
  - Remove the agent entry on the manager with `manage_agents -r <id>`, and confirm with
    `agent_control -l` that only `000` is left.
  - Restore the `pre-eslabon-v2` snapshot on Kali.
  - Commit `docs/evidence/e7/` with `docs: E7 lab evidence (three-layer measurement)`.

---

## Stage E8: Publish

**Exit condition:** the six items of §1 are ticked in `README.md`, each linked to its proof:
a test file, `docs/measurements.md`, `docs/evidence/e7/` and the writeup.

### Task 19: README, roadmap, final reviews, writeup

**Files:**
- Create: `README.md`, `docs/roadmap.md`
- External: `../02-writeups/<date>-eslabon-v2.md`, using `../02-writeups/_plantilla.md`

- [ ] **Step 1:** Write `docs/roadmap.md` from §3 "Out", in the same order. The first item
  carries the real-samples procedure: snapshot, clone the dataset, decrypt inside Kali,
  export only results, restore.
- [ ] **Step 2:** Write `README.md` in English. It must contain:
  - what it is, in 3 lines, and how it differs from eslabon v1 and GuardDog;
  - quick start;
  - the rule table with ATT&CK and mitigation;
  - the measured false-positive table;
  - the three-layer lab result;
  - *"What this does not detect"*, with the §5 residual gaps and the Wazuh ATT&CK v13.1
    note;
  - the security model summary.
- [ ] **Step 3:** Run the `simplify` skill on the whole branch. Re-run the full suite and
  ruff afterwards.
- [ ] **Step 4:** Run the `code-review` skill. Fix the findings test-first.
- [ ] **Step 5:** Write the writeup with the template's 8 sections, keeping the angle of
  *mitigation → residual gap → what to detect*.
- [ ] **Step 6:** Use `superpowers:finishing-a-development-branch`. Publishing (a push, and
  how v2 sits next to v1 on GitHub) needs the user's explicit confirmation.
