"""integrations/: Wazuh rules, agent snippet, Sigma rule and its translation.

Everything here is offline. The Wazuh rule tree is checked with a small Python
model of how the manager walks ``if_sid`` children (Wazuh emits ONE alert per
event, so exactly one leaf may match each event). The logtest samples are not
committed (their evidence snippets would trip the repo guard in
test_esl003.py); they are generated into a temp dir by
scripts/make_logtest_samples.py, which runs the real scan path.
"""

from __future__ import annotations

import importlib.util
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import jsonschema
import pytest

from eslabon.catalog import load_catalog

ROOT = Path(__file__).parent.parent
WAZUH = ROOT / "integrations" / "wazuh"
SIGMA = ROOT / "integrations" / "sigma"
RULES_XML = WAZUH / "eslabon_v2_rules.xml"
SNIPPET = WAZUH / "agent-ossec.conf.snippet"
SIGMA_RULE = SIGMA / "eslabon_v2_known_malicious.yml"
MAPPING = SIGMA / "MAPPING.md"
SCHEMA = json.loads((ROOT / "schema" / "event.schema.json").read_text("utf-8"))
LOCATION = "/var/log/eslabon/events.jsonl"

_GEN_PATH = ROOT / "scripts" / "make_logtest_samples.py"
_spec = importlib.util.spec_from_file_location("make_logtest_samples", _GEN_PATH)
assert _spec is not None and _spec.loader is not None
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

# sample file -> the one leaf rule it must reach
EXPECTED_LEAF = {
    "esl-001.jsonl": "100301",
    "esl-002.jsonl": "100302",
    "esl-003.jsonl": "100303",
    "esl-004.jsonl": "100304",
    "esl-005.jsonl": "100305",
    "esl-006.jsonl": "100306",
    "scan-ok.jsonl": "100310",
    "scan-incomplete.jsonl": "100311",
    "scan-osv-unavailable.jsonl": "100311",
}
# the subset of OS_Regex whose meaning is identical in Python re: literals,
# anchors and an escaped dot. Anything richer would make the model below lie.
_SAFE_REGEX = re.compile(r"^\^?(?:[A-Za-z0-9_-]|\\\.)+\$?$")
_SAFE_LOCATION = re.compile(r"^(?:[A-Za-z0-9_/-]|\\\.|\.)+\$?$")


# ------------------------------------------------------------ the model ----


def _rules() -> list[ET.Element]:
    root = ET.parse(RULES_XML).getroot()  # noqa: S314 -- our own committed file
    return list(root.iter("rule"))


def _model() -> dict[str, dict]:
    """id -> {level, parent, fields, location, decoded_as, mitre, groups}."""
    out: dict[str, dict] = {}
    for r in _rules():
        fields = [
            (f.get("name"), f.text or "", f.get("negate") == "yes")
            for f in r.findall("field")
        ]
        out[r.get("id")] = {
            "level": int(r.get("level")),
            "parent": r.findtext("if_sid"),
            "fields": fields,
            "location": r.findtext("location"),
            "decoded_as": r.findtext("decoded_as"),
            "mitre": [m.text for m in r.findall("mitre/id")],
            "groups": [g.text or "" for g in r.findall("group")],
        }
    return out


def _value(event: dict, dotted: str) -> str | None:
    cur: object = event
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    if isinstance(cur, (dict, list)):
        return None  # none of our rules match on objects or arrays
    return str(cur)


def _own_match(rule: dict, event: dict, location: str, decoder: str) -> bool:
    if rule["decoded_as"] is not None and rule["decoded_as"] != decoder:
        return False
    if rule["location"] is not None and not re.search(rule["location"], location):
        return False
    for name, regex, negate in rule["fields"]:
        value = _value(event, name)
        if value is None:
            return False  # an absent field never matches, negated or not
        if bool(re.search(regex, value)) == negate:
            return False
    return True


def _matching_leaves(event: dict, location: str = LOCATION, decoder: str = "json"):
    model = _model()
    parents = {r["parent"] for r in model.values() if r["parent"]}

    def matches(rid: str) -> bool:
        rule = model[rid]
        if rule["parent"] is not None and not matches(rule["parent"]):
            return False
        return _own_match(rule, event, location, decoder)

    return [rid for rid in model if rid not in parents and matches(rid)]


@pytest.fixture(scope="module")
def samples(tmp_path_factory) -> dict[str, list[dict]]:
    out = tmp_path_factory.mktemp("logtest-samples")
    gen.generate(out)
    result = {}
    for path in sorted(out.iterdir()):
        raw = path.read_bytes()
        assert raw.isascii() and raw.endswith(b"\n") and b"\r" not in raw
        result[path.name] = [json.loads(x) for x in raw.decode("ascii").splitlines()]
    return result


# ------------------------------------------------------------- the XML ----


def test_xml_levels_and_mitre_match_catalog():
    model = _model()
    catalog = load_catalog()
    for n, (rid, rule) in enumerate(sorted(catalog.items()), start=1):
        xml_rule = model[f"10030{n}"]
        assert rid == f"ESL-00{n}"
        assert ("rule.id", f"^{rid}$", False) in xml_rule["fields"]
        assert xml_rule["level"] == rule.wazuh_level, rid
        assert xml_rule["mitre"] == rule.wazuh_mitre, rid
    assert len(catalog) == 6


def test_xml_ids_in_range_and_unique():
    ids = [r.get("id") for r in _rules()]
    assert len(ids) == len(set(ids))
    assert sorted(ids) == [
        "100300", "100301", "100302", "100303", "100304", "100305", "100306",
        "100310", "100311",
    ]
    for rid in ids:
        assert 100300 <= int(rid) <= 100399
        assert not 100100 <= int(rid) <= 100199  # eslabon v1 lives there


def test_no_level_15():
    for rule in _model().values():
        assert 0 <= rule["level"] <= 14


def test_every_rule_in_group_eslabon_v2_and_parent_shape():
    model = _model()
    for rid, rule in model.items():
        groups = ",".join(rule["groups"]).split(",")
        assert "eslabon_v2" in groups, rid
        assert "eslabon" not in groups, rid  # v1's group
    parent = model["100300"]
    assert parent["level"] == 0 and parent["parent"] is None
    assert parent["decoded_as"] == "json"
    assert parent["location"] == r"events\.jsonl$"
    assert parent["fields"] == [("event.module", "^eslabon$", False)]
    for rid, rule in model.items():
        if rid != "100300":
            assert rule["parent"] == "100300", rid
            assert rule["location"] is None and rule["decoded_as"] is None


def test_xml_regexes_are_in_the_safe_subset():
    # the tree model uses Python re; that is exact only for this subset
    for rid, rule in _model().items():
        for name, regex, _ in rule["fields"]:
            assert _SAFE_REGEX.fullmatch(regex), (rid, name, regex)
        if rule["location"] is not None:
            assert _SAFE_LOCATION.fullmatch(rule["location"]), rid


def test_scan_rules_shape():
    model = _model()
    ok, other = model["100310"], model["100311"]
    assert ok["level"] == 3 and other["level"] == 7
    assert ("event.dataset", r"^eslabon\.scan$", False) in ok["fields"]
    assert ("event.dataset", r"^eslabon\.scan$", False) in other["fields"]
    assert ("eslabon.scan.status", "^ok$", False) in ok["fields"]
    assert ("eslabon.scan.status", "^ok$", True) in other["fields"]
    for n in range(1, 7):
        assert ("event.dataset", r"^eslabon\.finding$", False) in model[
            f"10030{n}"
        ]["fields"]


def test_descriptions_interpolate_our_fields():
    for r in _rules():
        desc = r.findtext("description") or ""
        assert desc.isascii() and desc.startswith("Eslabon v2:")
        if r.get("id") in {f"10030{n}" for n in range(1, 7)}:
            assert "$(package.name)" in desc and "$(rule.name)" in desc
    other = [r for r in _rules() if r.get("id") == "100311"][0]
    assert "$(eslabon.scan.status)" in other.findtext("description")


def test_rule_tree_one_alert_per_event(samples):
    assert sorted(samples) == sorted(EXPECTED_LEAF)
    for name, events in samples.items():
        assert len(events) == 1, name
        assert _matching_leaves(events[0]) == [EXPECTED_LEAF[name]], name


def test_rule_tree_ignores_other_sources(samples):
    finding = samples["esl-006.jsonl"][0]
    # eslabon v1's file, stdin (wazuh-logtest default), another decoder
    for location in ("/var/log/eslabon/eventos.jsonl", "stdin"):
        assert _matching_leaves(finding, location=location) == []
    assert _matching_leaves(finding, decoder="syslog") == []
    other_module = json.loads(json.dumps(finding))
    other_module["event"]["module"] = "eslabon-v1"
    assert _matching_leaves(other_module) == []
    unknown_rule = json.loads(json.dumps(finding))
    unknown_rule["rule"]["id"] = "ESL-0066"
    assert _matching_leaves(unknown_rule) == []


# ------------------------------------------------------------- samples ----


def test_logtest_samples_validate_against_schema(samples):
    catalog = load_catalog()
    for name, events in samples.items():
        for ev in events:
            jsonschema.validate(ev, SCHEMA)
        ev = events[0]
        if name.startswith("esl-"):
            rid = "ESL-" + name[4:7]
            assert ev["event"]["dataset"] == "eslabon.finding"
            assert ev["rule"]["id"] == rid
            assert ev["rule"]["name"] == catalog[rid].name
        else:
            assert ev["event"]["dataset"] == "eslabon.scan"
    status = {n: e[0]["eslabon"]["scan"]["status"] for n, e in samples.items()
              if n.startswith("scan-")}
    assert status == {
        "scan-ok.jsonl": "ok",
        "scan-incomplete.jsonl": "incomplete",
        "scan-osv-unavailable.jsonl": "osv_unavailable",
    }


def test_generator_refuses_an_out_dir_inside_the_repo():
    with pytest.raises(SystemExit):
        gen.main(["--out", str(WAZUH / "logtest-samples")])
    assert not (WAZUH / "logtest-samples").exists()


def test_no_samples_committed():
    # evidence snippets would trip the repo guard: generate on demand instead
    assert list(WAZUH.glob("**/*.jsonl")) == []


# ------------------------------------------------------- agent snippet ----


def test_agent_snippet_is_one_json_localfile():
    text = SNIPPET.read_text("ascii")
    root = ET.fromstring("<root>" + text + "</root>")  # noqa: S314 -- our own file
    files = root.findall("localfile")
    assert len(files) == 1 and len(list(root)) == 1
    assert files[0].findtext("location") == LOCATION
    assert files[0].findtext("log_format") == "json"


# --------------------------------------------------------------- Sigma ----


def _sigma_top_level() -> dict[str, str]:
    """Top-level ``key: value`` pairs (value '' for block keys); stdlib only."""
    out = {}
    for line in SIGMA_RULE.read_text("ascii").splitlines():
        m = re.match(r"^([a-z_]+):\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def _sigma_block(key: str) -> list[str]:
    lines = SIGMA_RULE.read_text("ascii").splitlines()
    start = lines.index(f"{key}:")
    block = []
    for line in lines[start + 1 :]:
        if line and not line.startswith(" "):
            break
        if line.strip():
            block.append(line.rstrip())
    return block


def test_sigma_targets_esl006_and_maps_to_100306():
    top = _sigma_top_level()
    for key in (
        "title", "id", "status", "description", "author", "date", "references",
        "tags", "logsource", "detection", "falsepositives", "level",
    ):
        assert key in top, key
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        top["id"],
    )
    assert top["status"] == "experimental"
    assert top["level"] == "high"
    assert re.fullmatch(r"\d{4}/\d{2}/\d{2}", top["date"])
    assert "ESL-006" in top["title"]
    tags = [x.strip() for x in _sigma_block("tags")]
    assert tags == ["- attack.initial_access", "- attack.t1195.001"]
    assert [x.strip() for x in _sigma_block("logsource")] == [
        "product: eslabon", "category: package_scan",
    ]
    assert [x.strip() for x in _sigma_block("detection")] == [
        "selection:",
        "event.module: eslabon",
        "event.dataset: eslabon.finding",
        "rule.id: ESL-006",
        "condition: selection",
    ]
    mapping = MAPPING.read_text("ascii")
    assert "100306" in mapping and "100320" not in RULES_XML.read_text("ascii")
    for sigma_field, wazuh in (
        ("event.module", '<field name="event.module">^eslabon$</field>'),
        ("event.dataset", r'<field name="event.dataset">^eslabon\.finding$</field>'),
        ("rule.id", '<field name="rule.id">^ESL-006$</field>'),
    ):
        assert sigma_field in mapping and wazuh in mapping, sigma_field


def test_sigma_translation_is_rule_100306():
    # the Sigma selection, applied to rule 100306's fields (parent included)
    model = _model()
    fields = model["100300"]["fields"] + model["100306"]["fields"]
    assert sorted(fields) == sorted(
        [
            ("event.module", "^eslabon$", False),
            ("event.dataset", r"^eslabon\.finding$", False),
            ("rule.id", "^ESL-006$", False),
        ]
    )
    assert model["100306"]["level"] == 13  # Sigma "high"; no level 15


def test_integration_files_are_ascii():
    for path in (*WAZUH.rglob("*"), *SIGMA.rglob("*")):
        if path.is_file():
            assert path.read_bytes().isascii(), path
