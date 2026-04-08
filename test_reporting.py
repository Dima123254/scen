# -*- coding: utf-8 -*-
"""Тесты отчётов и приложений."""

from __future__ import annotations

from pathlib import Path

from core.data_loader import load_company_data, load_validation_config
from reporting.fstec_appendices import appendix11_rows, build_appendix
from reporting.report_generator import ReportGenerator
from validation.filter_engine import FilterEngine


def _company():
    return load_company_data(Path(__file__).parent / "test_data" / "org_alpha.json")


def _vcfg():
    return load_validation_config(
        Path(__file__).resolve().parent.parent / "config" / "validation_config.yaml"
    )


def test_appendix11_rows():
    rows = appendix11_rows()
    assert any(r["Тактика"] == "Т1" for r in rows)


def test_build_appendix_6():
    title, rows = build_appendix(6, _company())
    assert "Приложение 6" in title
    assert len(rows) >= 1


def test_validation_report_files(tmp_path):
    company = _company()
    from core.scenario_builder import ThreatScenarioBuilder

    b = ThreatScenarioBuilder({})
    sc = [b.build_scenario("УБИ.1", company.attackers[0], company.assets[-1], company, 0)]
    fe = FilterEngine(company, _vcfg())
    rep = fe.run(sc)
    rg = ReportGenerator()
    paths = rg.generate_validation_report(rep, tmp_path / "val", ["json", "txt"])
    assert len(paths) == 2
    assert paths[0].exists()


def test_fstec_appendix_xlsx(tmp_path):
    rg = ReportGenerator()
    p = rg.generate_fstec_appendix(11, _company(), tmp_path / "a11.xlsx", fmt="xlsx")
    assert p.exists()
