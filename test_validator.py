# -*- coding: utf-8 -*-
"""Тесты фильтров валидации."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.data_loader import load_company_data, load_validation_config
from core.scenario_builder import ThreatScenarioBuilder
from validation.filter_engine import FilterEngine
from validation.scenario_validator import ScenarioValidator


def _company(name: str):
    return load_company_data(Path(__file__).parent / "test_data" / name)


def _vcfg():
    return load_validation_config(
        Path(__file__).resolve().parent.parent / "config" / "validation_config.yaml"
    )


def _scenario_for(company, ubi: str = "УБИ.1"):
    b = ThreatScenarioBuilder({})
    return b.build_scenario(ubi, company.attackers[0], company.assets[-1], company, 0)


def test_topology_passes_with_dmz():
    company = _company("org_alpha.json")
    v = ScenarioValidator(company, _vcfg())
    sc = _scenario_for(company)
    r = v.validate_one(sc, ["topology"])
    assert r.results[0].passed


def test_topology_fails_direct_external_internal():
    company = _company("org_beta.json")
    v = ScenarioValidator(company, _vcfg())
    sc = _scenario_for(company)
    r = v.validate_one(sc, ["topology"])
    assert not r.results[0].passed


def test_level_fails_n1_with_t8():
    company = _company("org_alpha.json")
    sc = _scenario_for(company)
    sc["attacker"]["level"] = "Н1"
    v = ScenarioValidator(company, _vcfg())
    r = v.validate_one(sc, ["level"])
    assert not r.results[0].passed


def test_interface_fails_no_overlap():
    company = _company("org_alpha.json")
    sc = _scenario_for(company)
    sc["attacker"]["interfaces"] = ["vpn_only"]
    sc["asset"]["interfaces"] = ["web"]
    v = ScenarioValidator(company, _vcfg())
    r = v.validate_one(sc, ["interface"])
    assert not r.results[0].passed


def test_ubi_consistency():
    company = _company("org_alpha.json")
    sc = _scenario_for(company)
    v = ScenarioValidator(company, _vcfg())
    r = v.validate_one(sc, ["ubi"])
    assert r.results[0].passed


def test_filter_engine_summary():
    company = _company("org_alpha.json")
    b = ThreatScenarioBuilder({})
    scenarios = [b.build_scenario("УБИ.1", company.attackers[0], company.assets[-1], company, i) for i in range(2)]
    fe = FilterEngine(company, _vcfg())
    rep = fe.run(scenarios)
    assert "level" in rep.summary_by_filter
    assert len(rep.per_scenario) == 2


def test_filter_subset():
    company = _company("org_alpha.json")
    sc = _scenario_for(company)
    fe = FilterEngine(company, _vcfg())
    rep = fe.run([sc], filter_subset=["ubi"])
    assert len(rep.per_scenario[0]["filters"]) == 1
