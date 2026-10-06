# Eslabon event schema (schema_version 1.0)

Contract: `schema/event.schema.json` (JSON Schema draft 2020-12) enforces this document.
`jsonschema` is a dev dependency used by tests only; the runtime never imports it.

ECS reference: **9.5.0**, the latest release of elastic/ecs, published 2026-08-04T14:33:55Z.
Source: GitHub API `repos/elastic/ecs/releases/latest`, checked 2026-10-05. ATT&CK data: v19.2.

Every line of the output file is one JSON object, ASCII only (`ensure_ascii`), LF-terminated,
no BOM, and always under 65,000 bytes (`MAX_LINE_BYTES`, newline excluded). The limit is
set by Wazuh 4.14's logcollector, not by JSON: its `read_json` reads each line with
`fgets` into `OS_MAXSTR - OS_LOG_HEADER` bytes, so at most 65,278 bytes plus the newline
arrive. Measured in the E7 lab: a 65,300-byte line was dropped silently and the line
after it was lost as well. The emitter raises `ValueError` instead of writing a line at
or over the limit.

## Deviation from ECS: no `file.*`

ECS puts an artifact's hash in `file.hash.sha256`. Eslabon does **not**: the archive
hash is `eslabon.archive.sha256`, and no event has a top-level `file` key (the schema
rejects one). Reason, measured in the E7 lab: Wazuh 4.14's `wazuh-alerts` index
template maps `data.file` as a `keyword`, and a decoded JSON event lands under `data.`,
so an object at `file` makes OpenSearch reject the **whole** alert (filebeat
`mapper_parsing_exception` 14 times, 0 alerts indexed). Every other ECS field
Eslabon uses is unaffected.

## Event kinds

- **Finding** - `event.kind=alert`, `event.dataset=eslabon.finding`. One per rule match.
- **Scan summary** - `event.kind=event`, `event.dataset=eslabon.scan`. One per scan, so that
  "zero findings" and "nothing arrived" are distinguishable. No rule, threat, evidence or
  mitigation fields.

## Fields

"Attacker" = the value derives from archive content or metadata. It is passed through
`clean_text` (control, ANSI and bidi characters removed) and truncated.

| Field | Type | Meaning | Attacker? |
|---|---|---|---|
| `@timestamp` | string | UTC, ISO 8601 with milliseconds and `Z` | no |
| `ecs.version` | string | ECS release this document was written against | no |
| `event.kind` | string | `alert` (finding) or `event` (summary) | no |
| `event.category` | string[] | Findings only: `package`, `malware` | no |
| `event.type` | string[] | Findings only: `info` | no |
| `event.module` | string | Always `eslabon` | no |
| `event.dataset` | string | `eslabon.finding` or `eslabon.scan` | no |
| `event.severity` | integer | Findings only: rule severity 1-10 | no |
| `event.outcome` | string | Summary only: `success` if status is `ok`, else `failure` | no |
| `rule.id` | string | Findings only: `ESL-001`..`ESL-006` | no |
| `rule.name` | string | Findings only: rule name | no |
| `rule.ruleset` | string | Findings only: `eslabon` | no |
| `rule.version` | string | Findings only: Eslabon version | no |
| `threat.framework` | string | Findings only: `MITRE ATT&CK` | no |
| `threat.technique.id` / `.name` | string[] | Findings only: technique IDs and names | no |
| `threat.tactic.id` / `.name` | string[] | Findings only: tactic IDs and names | no |
| `package.name` | string | Name from metadata or the request; `unknown` if absent. Max 512 chars. For a local archive it is read from inside it (see below) | yes |
| `package.version` | string | Version, same origin. Max 512 chars | yes |
| `eslabon.schema_version` | string | `1.0` | no |
| `eslabon.attack_version` | string | `19.2` | no |
| `eslabon.ecosystem` | string | `pypi` or `npm` | no |
| `eslabon.scan_id` | string | Identifier shared by all events of one scan | no |
| `eslabon.archive.sha256` | string | SHA-256 of the **archive**, lowercase hex. The whole `eslabon.archive` object is omitted when the hash is unknown (archive never opened) | no |
| `eslabon.identity_source` | string | Summary only, **optional**: where the package name checked by ESL-005 came from: `metadata`, `filename` (metadata missing or ambiguous, so the archive's file name was used) or `argument` (a `name==version` target). Absent when no name was available | no |
| `eslabon.evidence.file` | string | Findings only: the **inner** file that matched (package-level rules: the checked name for ESL-005, `<osv>` for ESL-006). Max 512 chars | yes |
| `eslabon.evidence.line` | integer | Findings only: line number of the match | no |
| `eslabon.evidence.snippet` | string | Findings only: matched text. Max 1,024 chars | yes |
| `eslabon.evidence.name_hex` | string | Findings only: hex of the raw member name, max 1,024 chars | yes |
| `eslabon.evidence.match_count` | integer | Findings only: matches in that file | no |
| `eslabon.mitigation.action` / `.residual_gap` / `.detect` | string | Findings only: catalog text | no |
| `eslabon.scan.status` | string | `ok`, `timeout`, `limits_exceeded`, `parse_error`, `hash_mismatch`, `fetch_error`, `incomplete`, `osv_unavailable` (see below) | no |
| `eslabon.scan.files_scanned` / `bytes_read` | integer | Work done. `bytes_read` differs by format: for a zip/wheel it is the decompressed bytes of the members read; for a tar it is the whole decompressed stream (headers, padding and skipped members included) | no |
| `eslabon.scan.findings` / `anomalies` | integer | Counts. If writing the finding events fails (status downgraded to `parse_error`), `findings` can exceed the finding events actually written | no |
| `eslabon.scan.anomaly_kinds` | string[] | Sorted unique anomaly kinds | no |
| `eslabon.scan.osv_status` | string | `ok`, `unavailable`, `skipped` (see below) | no |
| `eslabon.scan.duration_ms` | integer | Wall-clock duration | no |
| `eslabon.scan.error` | string | Only when an error exists. Max 512 chars | yes |

## OSV status (ESL-006)

`osv_status` is `ok` when every identity name was looked up, `unavailable` when any lookup
failed (network, HTTP, size cap, redirect off `https://api.osv.dev`, bad JSON, the
10-page cap or the 30 s overall deadline) **or when the archive gave no package name to
ask about** (no usable metadata and no name in its file name). `unavailable` makes the
status `osv_unavailable` (exit 2) unless something worse already applies. `skipped` means
only one thing: the user passed `--offline`. With `--offline` the exit code comes from
the other statuses alone, even for a nameless archive (the user opted out of the lookup).

Each identity name is queried with its own version: the metadata name with the metadata
version, a differing file-name name with the version in the file name; no version (all
advisories for that name) only when none can be parsed.

Limits: for local archives ESL-006 trusts the name and version the archive **declares**.
A known-bad artifact that is renamed or re-versioned is not matched (the content rules
ESL-001..004 cover edited artifacts), and a `MAL-` record that lists specific versions
can be dodged by declaring another version.

## Scan status

When several statuses apply, the first one in this list wins:
`timeout` > `limits_exceeded` > `parse_error` > `hash_mismatch` > `fetch_error` >
`incomplete` > `osv_unavailable` > `ok`.

`incomplete` means content existed that was not scanned: an anomaly of kind
`encrypted_member`, `unsupported_compression`, `bad_member` (a member whose read failed,
or a GNU sparse tar member) or `package_json_too_deep` (an npm `package.json` at the package
root nested too deep for Python's JSON parser; npm's parser reads it, so its install scripts
and the package identity went unchecked) or `no_identity` (no package name from the
`name==version` argument, the metadata or the archive file name, so ESL-005/006 could not
run; also with `--offline`) was recorded. These anomaly kinds do **not** make a scan
incomplete: `weak_hash_sha1` (a `name==version` npm download verified only against the
registry's sha1 `shasum`, because no sha512 `integrity` is published), `temp_leftover` (a
`name==version` scan could not remove the temporary directory holding the downloaded
archive; the detail is its path, also printed as one stderr warning), `special_member` (tar FIFO, character or block device: no content),
`overlapped_entry` (zip entries sharing one local header: the data was read and scanned),
and `dir_with_content` (a zip entry that looks like a directory but carries data, or whose stored
and host-mapped names disagree: it is read and scanned as a regular member), and
`bad_package_json` (an npm `package.json` at the package root with a JSON syntax error or
a root that is not an object: npm itself refuses to install it, so ESL-002 records no
finding for it; the bytes were still matched by the other rules). `package.json` is read
the way npm reads it, `JSON.parse(stripBOM(String(buffer)))`: invalid UTF-8 becomes U+FFFD
and one leading BOM is dropped, so neither is an anomaly.

Exit code of `eslabon scan`: 2 for every status other than `ok` (and for any usage or IO
error), 1 if the status is `ok` and there are findings, 0 otherwise.

## Package metadata of a local archive

Name and version are read during the same streaming pass that scans the members. The
metadata file is chosen by archive kind, and Eslabon refuses to guess:

- wheel (zip, pypi): only `<x>.dist-info/METADATA` (RFC 822 `Name:` / `Version:`), and the
  archive must contain exactly one `.dist-info` directory;
- sdist (tar, pypi): only `<single top dir>/PKG-INFO` (same headers), and the archive must
  have a single top-level directory;
- npm: only a `package.json` whose raw path has exactly two components
  (`package/package.json`); a bare top-level `package.json` is ignored, because npm strips
  the first component.

Members whose names were rewritten by normalisation (traversal, absolute path) or contain a
`\` are never candidates. If such a member would be a candidate under any reading
(`\` as `/`, `..` resolved or dropped), the result is `ambiguous_metadata`, because some
installer could let it win. More than one candidate, or several `.dist-info` directories, gives the anomaly
kind `ambiguous_metadata` and no name. No candidate, or a malformed one, gives `no_metadata`
(only when the scan status is otherwise `ok`). An npm candidate nested too deep for Python's
parser gives `package_json_too_deep` instead, and the status `incomplete`. In both cases `package.name` is `unknown`.
The values are attacker-controlled.

Zip names are judged as stored in the archive (`ZipInfo.orig_filename`), never as the
scanner's host OS maps them, so the verdict is the same on Windows and POSIX. A malformed,
Windows-built wheel that uses `\` as a separator may therefore get
`ambiguous_metadata`. That stays an anomaly; the status remains `ok`. A NUL in a member
name is treated like a rewritten name.

## Package identity and ESL-005

ESL-005 (typosquat) is a package-level rule: it runs once per scan, in the parent
process after the worker returns, on the name the package claims to be. Its finding has
`eslabon.evidence.file` = the checked name, `line` = 0 and a snippet
`"<name> ~ <target> (distance N)"` or `"<name> ~ <target> (scope confusion)"`.

An attacker can switch identity checks off by breaking the metadata (`no_metadata`,
`ambiguous_metadata`). So when the metadata gives no name, ESL-005 falls back to the name in
the archive's **file** name (wheel: the first `-` field of `{name}-{ver}-...whl`; sdist and
npm: the suffix `.tar.gz`/`.tgz`/`.tar.bz2`/`.zip` is stripped and the name ends at the
last `-` followed by a digit). When a metadata name exists, a file stem that starts with a
spelling of it followed by `-<digit>` gives that prefix first, so a rebuild suffix
(`pyyaml-6.0-1.tar.gz`) is not a mismatch. `eslabon.identity_source` records which one was used.
`package.name` stays metadata-only (`unknown` in that case).

If both names exist and differ after normalisation (PEP 503 for PyPI; for npm a scoped
`@scope/name` matches a file named `name-<ver>.tgz` or `scope-name-<ver>.tgz`), **both** are
checked and the anomaly kind `identity_mismatch` is recorded. It does not make the scan
`incomplete`. Names longer than 214 characters (npm's maximum) are not checked: they cannot
be within distance 2 of a top-1,000 name.

## Duplicate members

All copies are scanned and reported: every copy of a duplicated name gets its own findings,
and duplicates are flagged with the `duplicate_name` anomaly. Which copy an installer leaves
on disk depends on the installer, the OS and how it maps names (traversal, `\`, NUL,
directory entries), so the scanner never drops a finding on that guess.

## Versioning

`eslabon.schema_version` bumps whenever the meaning of an existing field changes or a field
is removed. Adding an optional field does not require a bump.

## Wazuh notes

- Wazuh turns every value into a string; do not rely on numeric types in rules.
- Arrays contain strings only (the JSON decoder does not support arrays of objects).
- Keep each line under 65,000 bytes (see the top of this document); the emitter raises
  `ValueError` rather than write a longer one.
- `eslabon.archive.*` describes the archive; `eslabon.evidence.file` is the file inside it.
  Never add a top-level `file` object (see "Deviation from ECS").
- Lone surrogates from tar names are escaped as `\udXXX` by the ASCII JSON encoding, so the
  line stays valid JSON.
