# -*- coding: utf-8 -*-
"""Тесты маппинга УБИ / ФСТЭК / MITRE."""

from __future__ import annotations

from config.mapping_config import (
    attacker_level_rank,
    level_allows_tactic,
    normalize_fstec_tactic,
)
from core.threat_mapper import fstec_to_mitre, ubi_tactics


def test_normalize_t10_sub():
    assert normalize_fstec_tactic("Т10.3") == "Т10"


def test_ubi_tactics():
    assert "Т9" in ubi_tactics("УБИ.1")


def test_fstec_to_mitre():
    m = fstec_to_mitre("Т2")
    assert "Initial Access" in m.get("mitre_tactic", "")


def test_level_allows():
    assert level_allows_tactic("Н4", "Т8")
    assert not level_allows_tactic("Н1", "Т8")


def test_attacker_level_rank():
    assert attacker_level_rank("Н3") > attacker_level_rank("Н1")
