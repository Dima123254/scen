# -*- coding: utf-8 -*-
"""Матрица сценария (HTML)."""

from __future__ import annotations

from pathlib import Path

from core.data_loader import load_company_data, load_matrix_display
from core.scenario_builder import ThreatScenarioBuilder
from visualization.matrix_visualizer import build_matrix_html, export_matrix_html


def _scenario():
    company = load_company_data(Path(__file__).parent / "test_data" / "org_alpha.json")
    b = ThreatScenarioBuilder({})
    return b.build_scenario("УБИ.2", company.attackers[0], company.assets[-1], company, 0)


def test_build_matrix_html_contains_tactic_title():
    root = Path(__file__).resolve().parent.parent
    cfg = load_matrix_display(root)
    html_doc = build_matrix_html(_scenario(), cfg)
    assert "Сбор информации" in html_doc
    assert "СП." in html_doc
    assert "Способ реализации" in html_doc or "bdu.fstec.ru" in html_doc


def test_export_matrix(tmp_path):
    root = Path(__file__).resolve().parent.parent
    cfg = load_matrix_display(root)
    p = export_matrix_html(_scenario(), tmp_path / "m.html", cfg)
    assert p.exists()
    assert "html" in p.read_text(encoding="utf-8").lower()
