"""Rule catalog (ESL-001..006) loaded from the bundled catalog.toml."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from importlib import resources

_TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: int
    wazuh_level: int
    techniques: list[str]
    technique_names: list[str]
    tactics: list[str]
    tactic_names: list[str]
    action: str
    residual_gap: str
    detect: str
    wazuh_mitre: list[str]


def _wazuh_mitre(r: dict) -> list[str]:
    """IDs for the Wazuh XML <mitre>: the rule's techniques unless overridden.

    The override exists because Wazuh's bundled ATT&CK database is older than
    the catalog's (e.g. it lacks T1027.013); events keep `techniques`.
    """
    if "wazuh_mitre" not in r:
        return list(r["techniques"])
    ids = r["wazuh_mitre"]
    if (
        not isinstance(ids, list)
        or not ids
        or not all(isinstance(t, str) and _TECHNIQUE_ID.fullmatch(t) for t in ids)
        or len(set(ids)) != len(ids)
    ):
        raise ValueError(f"{r['id']}: bad wazuh_mitre {ids!r}")
    return list(ids)


def load_catalog() -> dict[str, Rule]:
    text = resources.files("eslabon").joinpath("catalog.toml").read_text("utf-8")
    data = tomllib.loads(text)
    tactic_names = data["tactics"]
    techs = {t["id"]: t for t in data["techniques"].values()}
    out: dict[str, Rule] = {}
    for r in data["rules"]:
        tactics: list[str] = []
        for tid in r["techniques"]:
            for ta in techs[tid]["tactics"]:
                if ta not in tactics:
                    tactics.append(ta)
        out[r["id"]] = Rule(
            id=r["id"],
            name=r["name"],
            severity=r["severity"],
            wazuh_level=r["wazuh_level"],
            techniques=list(r["techniques"]),
            technique_names=[techs[t]["name"] for t in r["techniques"]],
            tactics=tactics,
            tactic_names=[tactic_names[t] for t in tactics],
            action=r["action"],
            residual_gap=r["residual_gap"],
            detect=r["detect"],
            wazuh_mitre=_wazuh_mitre(r),
        )
    return out
