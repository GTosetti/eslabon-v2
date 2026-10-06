# Eslabon event schema (schema_version 1.0)

Contract: `schema/event.schema.json` (JSON Schema draft 2020-12) enforces this document.
`jsonschema` is a dev dependency used by tests only; the runtime never imports it.

ECS reference: **9.5.0**, the latest release of elastic/ecs, published 2026-08-04T14:33:55Z.
Source: GitHub API `repos/elastic/ecs/releases/latest`, checked 2026-10-05. ATT&CK data: v19.2.

Every line of the output file is one JSON object, ASCII only (`ensure_ascii`), LF-terminated,
no BOM, and always under 65,536 bytes.

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
| `file.hash.sha256` | string | SHA-256 of the **archive** (omitted if unknown) | no |
| `eslabon.schema_version` | string | `1.0` | no |
| `eslabon.attack_version` | string | `19.2` | no |
| `eslabon.ecosystem` | string | `pypi` or `npm` | no |
| `eslabon.scan_id` | string | Identifier shared by all events of one scan | no |
| `eslabon.evidence.file` | string | Findings only: the **inner** file that matched. Max 512 chars | yes |
| `eslabon.evidence.line` | integer | Findings only: line number of the match | no |
| `eslabon.evidence.snippet` | string | Findings only: matched text. Max 1,024 chars | yes |
| `eslabon.evidence.name_hex` | string | Findings only: hex of the raw member name, max 1,024 chars | yes |
| `eslabon.evidence.match_count` | integer | Findings only: matches in that file | no |
| `eslabon.mitigation.action` / `.residual_gap` / `.detect` | string | Findings only: catalog text | no |
| `eslabon.scan.status` | string | `ok`, `timeout`, `limits_exceeded`, `parse_error`, `hash_mismatch`, `fetch_error`, `incomplete`, `osv_unavailable` (see below) | no |
| `eslabon.scan.files_scanned` / `bytes_read` | integer | Work done. `bytes_read` differs by format: for a zip/wheel it is the decompressed bytes of the members read; for a tar it is the whole decompressed stream (headers, padding and skipped members included) | no |
| `eslabon.scan.findings` / `anomalies` | integer | Counts. If writing the finding events fails (status downgraded to `parse_error`), `findings` can exceed the finding events actually written | no |
| `eslabon.scan.anomaly_kinds` | string[] | Sorted unique anomaly kinds | no |
| `eslabon.scan.osv_status` | string | `ok`, `unavailable`, `skipped` | no |
| `eslabon.scan.duration_ms` | integer | Wall-clock duration | no |
| `eslabon.scan.error` | string | Only when an error exists. Max 512 chars | yes |

## Scan status

When several statuses apply, the first one in this list wins:
`timeout` > `limits_exceeded` > `parse_error` > `hash_mismatch` > `fetch_error` >
`incomplete` > `osv_unavailable` > `ok`.

`incomplete` means content existed that was not scanned: an anomaly of kind
`encrypted_member`, `unsupported_compression` or `bad_member` (a member whose read failed,
or a GNU sparse tar member) was recorded. These anomaly kinds do **not** make a scan
incomplete: `special_member` (tar FIFO, character or block device: no content),
`overlapped_entry` (zip entries sharing one local header: the data was read and scanned),
and `dir_with_content` (a zip entry that looks like a directory but carries data, or whose stored
and host-mapped names disagree: it is read and scanned as a regular member), and
`bad_package_json` (an npm `package.json` at the package root that is not UTF-8, not valid
JSON or not a JSON object: npm itself would refuse to install it, so ESL-002 records no
finding for it; the bytes were still matched by the other rules).

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
(only when the scan status is otherwise `ok`). In both cases `package.name` is `unknown`.
The values are attacker-controlled.

Zip names are judged as stored in the archive (`ZipInfo.orig_filename`), never as the
scanner's host OS maps them, so the verdict is the same on Windows and POSIX. A malformed,
Windows-built wheel that uses `\` as a separator may therefore get
`ambiguous_metadata`. That stays an anomaly; the status remains `ok`. A NUL in a member
name is treated like a rewritten name.

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
- Keep each line under 64 KB; the emitter raises `ValueError` rather than write a longer one.
- `file.*` describes the archive; `eslabon.evidence.file` is the file inside it.
- Lone surrogates from tar names are escaped as `\udXXX` by the ASCII JSON encoding, so the
  line stays valid JSON.
