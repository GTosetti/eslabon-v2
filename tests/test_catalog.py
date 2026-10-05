import pytest

from eslabon.catalog import load_catalog

SPEC = [
    ("ESL-001", "pypi-install-exec", 8, 11, ["T1546.016", "T1059.006"]),
    ("ESL-002", "npm-install-script-exec", 8, 11, ["T1546.016", "T1059.007"]),
    ("ESL-003", "encoded-exec", 9, 12, ["T1027.013", "T1140"]),
    ("ESL-004", "secret-exfil", 9, 12, ["T1552.001", "T1041"]),
    ("ESL-005", "typosquat", 5, 7, ["T1195.001"]),
    ("ESL-006", "known-malicious", 10, 13, ["T1195.001"]),
]


@pytest.mark.parametrize(("rid", "name", "sev", "level", "techs"), SPEC)
def test_six_rules_with_spec_values(rid, name, sev, level, techs):
    rule = load_catalog()[rid]
    assert rule.id == rid
    assert rule.name == name
    assert rule.severity == sev
    assert rule.wazuh_level == level
    assert rule.techniques == techs
    assert rule.wazuh_mitre == techs
    assert len(load_catalog()) == 6


def test_no_level_15():
    assert all(r.wazuh_level != 15 for r in load_catalog().values())


def test_mitigation_triplet_present_and_short():
    for r in load_catalog().values():
        for text in (r.action, r.residual_gap, r.detect):
            assert text.strip()
            assert len(text) <= 300


def test_names_and_ids_align():
    for r in load_catalog().values():
        assert len(r.technique_names) == len(r.techniques)
        assert len(r.tactic_names) == len(r.tactics)
        assert len(set(r.tactics)) == len(r.tactics)


def test_tactics_v19_2():
    c = load_catalog()
    assert c["ESL-001"].tactics == ["TA0003", "TA0004", "TA0002"]
    assert c["ESL-003"].tactic_names == ["Stealth"]
    assert c["ESL-004"].tactics == ["TA0006", "TA0010"]
    assert c["ESL-006"].tactics == ["TA0001"]
