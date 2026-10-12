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
    assert len(load_catalog()) == 6


def test_wazuh_mitre_defaults_to_techniques_except_esl003():
    # T1027.013 is absent from Wazuh's bundled MITRE db (logtest warning),
    # so ESL-003 overrides it with the parent; events keep the v19.2 IDs.
    c = load_catalog()
    assert c["ESL-003"].wazuh_mitre == ["T1027", "T1140"]
    assert c["ESL-003"].techniques == ["T1027.013", "T1140"]
    for rid, rule in c.items():
        if rid != "ESL-003":
            assert rule.wazuh_mitre == rule.techniques, rid


def _catalog_with(monkeypatch, extra):
    """load_catalog with `extra` TOML lines appended to rule ESL-001."""
    import eslabon.catalog as catalog_mod

    real = catalog_mod.resources.files("eslabon").joinpath("catalog.toml")
    text = real.read_text("utf-8")
    anchor = 'id = "ESL-001"\n'
    assert text.count(anchor) == 1
    text = text.replace(anchor, anchor + extra)

    class _Fake:
        def joinpath(self, _name):
            return self

        def read_text(self, _enc):
            return text

    monkeypatch.setattr(catalog_mod.resources, "files", lambda _pkg: _Fake())
    return catalog_mod.load_catalog


@pytest.mark.parametrize(
    "bad",
    [
        'wazuh_mitre = []\n',
        'wazuh_mitre = ["X1027"]\n',
        'wazuh_mitre = ["T1027.13"]\n',
        'wazuh_mitre = "T1027"\n',
        'wazuh_mitre = [1027]\n',
        'wazuh_mitre = ["T1027", "T1027"]\n',
    ],
)
def test_bad_wazuh_mitre_rejected(monkeypatch, bad):
    load = _catalog_with(monkeypatch, bad)
    with pytest.raises(ValueError):
        load()


def test_good_wazuh_mitre_override_loaded(monkeypatch):
    load = _catalog_with(monkeypatch, 'wazuh_mitre = ["T1546", "T1059.006"]\n')
    rule = load()["ESL-001"]
    assert rule.wazuh_mitre == ["T1546", "T1059.006"]
    assert rule.techniques == ["T1546.016", "T1059.006"]


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


ESL001_ACTION = (
    "Prefer wheels (no setup.py runs); build sdists only after review, "
    "in a sandboxed build (container or VM) with egress blocked."
)


def test_esl001_action_recommends_sandboxed_build():
    assert load_catalog()["ESL-001"].action == ESL001_ACTION


def test_no_catalog_text_recommends_disabling_build_isolation():
    for r in load_catalog().values():
        for text in (r.action, r.residual_gap, r.detect):
            assert "--no-build-isolation" not in text, r.id
