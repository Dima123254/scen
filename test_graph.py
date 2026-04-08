# -*- coding: utf-8 -*-
"""Тест визуализации."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.data_loader import load_company_data
from core.scenario_builder import ThreatScenarioBuilder
from visualization.graph_visualizer import GraphVisualizer, Network


@pytest.mark.skipif(Network is None, reason="pyvis not installed")
def test_export_html(tmp_path):
    company = load_company_data(Path(__file__).parent / "test_data" / "org_alpha.json")
    b = ThreatScenarioBuilder({})
    sc = b.build_scenario("УБИ.1", company.attackers[0], company.assets[-1], company, 0)
    gv = GraphVisualizer()
    out = gv.export_graph(sc, tmp_path / "g.html", format="html")
    assert out is not None
    assert out.exists()
