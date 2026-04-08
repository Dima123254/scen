# -*- coding: utf-8 -*-
"""БДУ: способы реализации угроз."""

from __future__ import annotations

from config.bdu_realization_methods import (
    BDU_OFFICIAL_SECTION_URL,
    BDU_TECHNIQUES,
    format_bdu_method_line,
    pick_bdu_realization_methods_for_ubi,
)


def test_bdu_url_constant():
    assert "bdu.fstec.ru" in BDU_OFFICIAL_SECTION_URL


def test_pick_ubi1_contains_network_exfil_paths():
    rows = pick_bdu_realization_methods_for_ubi("УБИ.1")
    ids = {r["id"] for r in rows}
    assert "СП.4.4" in ids


def test_format_line():
    r = pick_bdu_realization_methods_for_ubi("УБИ.2")[0]
    s = format_bdu_method_line(r)
    assert "—" in s
    assert r["id"] in s


def test_full_catalog_size():
    assert len(BDU_TECHNIQUES) >= 40
