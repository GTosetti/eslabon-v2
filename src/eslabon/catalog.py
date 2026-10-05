"""Rule catalog (ESL-001..006) loaded from the bundled catalog.toml."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from importlib import resources


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
            wazuh_mitre=list(r["techniques"]),
        )
    return out
