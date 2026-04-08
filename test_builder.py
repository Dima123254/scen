# -*- coding: utf-8 -*-
"""Тесты построителя сценариев."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.data_loader import load_company_data
from core.scenario_builder import ThreatScenarioBuilder, build_all_scenarios


def _load(name: str):
    p = Path(__file__).parent / "test_data" / name
    return load_company_data(p)


def test_build_tactic_chain_ubi1():
    b = ThreatScenarioBuilder({})
    chain = b.build_tactic_chain("УБИ.1")
    assert chain[0] == "Т1"
    assert chain[-1] == "Т10.1"
    assert "Т9" in chain


def test_build_scenario_shape():
    company = _load("org_alpha.json")
    b = ThreatScenarioBuilder({})
    sc = b.build_scenario(
        "УБИ.1",
        company.attackers[0],
        company.assets[2],
        company,
        0,
    )
    assert sc["ubi"] == "УБИ.1"
    assert sc["asset"]["id"] == "i1"
    assert "techniques_by_tactic" in sc
    assert sc["company_name"] == "Тестовая организация Alpha"


def test_build_all_scenarios_limit():
    company = _load("org_alpha.json")
    b = ThreatScenarioBuilder({})
    all_sc = build_all_scenarios(company, b, max_per_ubi=2)
    assert len(all_sc) <= 2


def test_techniques_for_subtactic():
    b = ThreatScenarioBuilder({})
    tech = b.get_techniques_for_tactic("Т10.1")
    assert "T1489" in tech or len(tech) >= 1


def test_build_scenario_has_fstec_block():
    company = _load("org_alpha.json")
    b = ThreatScenarioBuilder({})
    sc = b.build_scenario("УБИ.1", company.attackers[0], company.assets[-1], company, 0)
    assert "fstec_techniques_by_tactic" in sc
    assert "Т1" in sc["fstec_techniques_by_tactic"]
    assert sc["fstec_techniques_by_tactic"]["Т1"][0]["id"].startswith("T1.")
