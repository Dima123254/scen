# -*- coding: utf-8 -*-
"""База ФСТЭК Прил. 11 и маппинг уровней."""

from __future__ import annotations

from config.attacker_level_mapping import (
    UBI_TO_FINAL_TECHNIQUE,
    fstec_technique_parent_tactic,
    level_allows_fstec_technique,
    tactics_for_level_and_ubi,
)
from config.fstec_techniques_database import FSTEC_TACTICS_AND_TECHNIQUES


def test_t1_has_techniques():
    t1 = FSTEC_TACTICS_AND_TECHNIQUES["Т1"]["techniques"]
    assert "T1.1" in t1
    assert len(t1) >= 20


def test_parent_tactic():
    assert fstec_technique_parent_tactic("T10.1") == "Т10"
    assert fstec_technique_parent_tactic("T9.13") == "Т9"


def test_level_n1_blocks_t8_technique():
    assert not level_allows_fstec_technique("Н1", "T8.1")
    assert level_allows_fstec_technique("Н1", "T1.1")


def test_ubi_finals():
    assert "T10.1" in UBI_TO_FINAL_TECHNIQUE["УБИ.1"]


def test_tactics_for_n1_with_ubi1_includes_t9():
    finals = UBI_TO_FINAL_TECHNIQUE["УБИ.1"]
    tac = tactics_for_level_and_ubi("Н1", finals)
    assert "Т9" in tac
    assert "Т8" not in tac
