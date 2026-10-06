# Sigma to Wazuh: hand translation of `eslabon_v2_known_malicious.yml`

There is no official pySigma backend for Wazuh
(<https://github.com/wazuh/wazuh/issues/17568>), so the Sigma rule is translated by
hand. **Its translation is Wazuh rule `100306`** in
`integrations/wazuh/eslabon_v2_rules.xml`, together with its parent `100300`. There is
no separate Sigma rule (no `100320`).

## Why the translation is 100306 and not a rule of its own

Wazuh produces **one alert per event**: the first matching leaf of the rule tree wins
and the event stops there. A separate rule matching the same ESL-006 finding events
would compete with `100306` for them, and one of the two alerts would never be seen.
The Sigma selection is exactly the condition of `100306` (with its parent), so the
two are the same rule written in two languages. What is validated end to end in the
lab (E7) is that translation, `100306`, firing in `wazuh-alerts-*`; the Sigma file
itself is not run by any engine.

## Field mapping

The Wazuh `json` decoder exposes nested JSON keys as dotted field names, so each
Sigma field keeps its name. Values are matched as strings with the default
`osregex` type; the regexes are anchored so the match is exact (Sigma's default for
a plain value is an exact, case-insensitive match; ours are all lower case or fixed
upper-case IDs, so case does not matter here).

| Sigma field | Sigma value | Wazuh rule | Wazuh element (exact text) |
|---|---|---|---|
| `logsource.product: eslabon` | - | `100300` | `<decoded_as>json</decoded_as>` + `<location>events\.jsonl$</location>` |
| `event.module` | `eslabon` | `100300` | `<field name="event.module">^eslabon$</field>` |
| `event.dataset` | `eslabon.finding` | `100306` | `<field name="event.dataset">^eslabon\.finding$</field>` |
| `rule.id` | `ESL-006` | `100306` | `<field name="rule.id">^ESL-006$</field>` |

`rule.id` is **our** decoded field. In the alert it is stored as `data.rule.id`,
separate from Wazuh's own `rule.id` (`100306`). Confirming that in `wazuh-logtest`
is a design section 11 check for E7.

## Condition

| Sigma | Wazuh |
|---|---|
| `condition: selection` (all selection fields ANDed) | `<if_sid>100300</if_sid>` plus the `<field>` elements of `100306`: every `<field>` in a rule must match, and the parent's conditions must have matched first, so the whole chain is one AND |

## Level

| Sigma `level` | Wazuh `level` | Why |
|---|---|---|
| `high` | `13` | `catalog.toml` gives ESL-006 `wazuh_level = 13`. Sigma `critical` would suggest Wazuh 15, which this project never uses. |

## Tags

| Sigma tag | Wazuh |
|---|---|
| `attack.initial_access` | tactic TA0001, implied by the technique below |
| `attack.t1195.001` | `<mitre><id>T1195.001</id></mitre>` in `100306` |
