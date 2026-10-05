# Eslabon event schema (schema_version 1.0)

Contract: `schema/event.schema.json` (JSON Schema draft 2020-12) enforces this document.
`jsonschema` is a dev dependency used by tests only; the runtime never imports it.

ECS reference: **9.5.0**, taken from https://github.com/elastic/ecs/releases on 2026-10-05
(read through a summarising fetch tool; the publication date it reported, 2024-08-04, looks
doubtful, so re-check the version by hand before relying on it). ATT&CK data: v19.2.

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
| `package.name` | string | Name from metadata or the request; `unknown` if absent. Max 512 chars | yes |
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
| `eslabon.scan.status` | string | `ok`, `timeout`, `limits_exceeded`, `parse_error`, `hash_mismatch`, `fetch_error`, `osv_unavailable` | no |
| `eslabon.scan.files_scanned` / `bytes_read` | integer | Work done | no |
| `eslabon.scan.findings` / `anomalies` | integer | Counts | no |
| `eslabon.scan.anomaly_kinds` | string[] | Sorted unique anomaly kinds | no |
| `eslabon.scan.osv_status` | string | `ok`, `unavailable`, `skipped` | no |
| `eslabon.scan.duration_ms` | integer | Wall-clock duration | no |
| `eslabon.scan.error` | string | Only when an error exists. Max 512 chars | yes |

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
