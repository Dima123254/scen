# -*- coding: utf-8 -*-
"""Тест пакетного запуска."""

from __future__ import annotations

from pathlib import Path

from core.data_loader import load_company_data
from core.pipeline import run_generate_bundle


def test_run_generate_bundle(tmp_path):
    root = Path(__file__).resolve().parent.parent
    company = load_company_data(Path(__file__).parent / "test_data" / "org_alpha.json")
    r = run_generate_bundle(
        company,
        tmp_path,
        engine_root=root,
        validate=True,
        visualize=False,
        max_scenarios_per_ubi=2,
    )
    assert r.scenarios_count >= 1
    assert r.scenarios_path.exists()


def test_run_generate_bundle_matrix(tmp_path):
    root = Path(__file__).resolve().parent.parent
    company = load_company_data(Path(__file__).parent / "test_data" / "org_alpha.json")
    r = run_generate_bundle(
        company,
        tmp_path,
        engine_root=root,
        validate=False,
        visualize=True,
        max_scenarios_per_ubi=1,
        visualization_mode="matrix",
    )
    assert r.matrix_paths
    assert r.matrix_paths[0].exists()
